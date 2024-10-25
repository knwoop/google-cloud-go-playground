package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials/externalaccount"
	"cloud.google.com/go/storage"
	"github.com/110y/run"
	"github.com/110y/servergroup"
	"github.com/knwoop/google-cloud-go-playground/lib/env"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	port = flag.Int("port", 8081, "The server port")
	host = flag.String("host", "localhost", "host name")

	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
)

const (
	tokenEndpoint = "https://sts.googleapis.com/v1/token"
)

func main() {
	flag.CommandLine.SetOutput(os.Stdout)
	flag.Parse()

	run.Run(func(ctx context.Context) int {
		if err := serve(ctx, *port); err != nil {
			fmt.Fprintf(os.Stderr, "the server aborted: %s\n", err)
			return 1
		}
		return 0
	})
}

func serve(ctx context.Context, port int) error {
	e, err := env.LoadEnvironments()
	if err != nil {
		return fmt.Errorf("failed load envs: %w", err)
	}

	if err := loadOrCreateKeys(); err != nil {
		return fmt.Errorf("failed pub/priv keys: %w", err)
	}

	s := NewServer(port, e)

	var sg servergroup.Group
	sg.Add(s)

	if err := sg.Start(ctx); err != nil {
		return fmt.Errorf("failed start servers: %w", err)
	}

	return nil
}

var (
	_ servergroup.Server  = (*Server)(nil)
	_ servergroup.Stopper = (*Server)(nil)
)

type Server struct {
	env    *env.Environments
	server *http.Server

	httpClient *http.Client
}

func NewServer(port int, e *env.Environments) *Server {
	s := &Server{
		env: e,
		server: &http.Server{
			Addr: fmt.Sprintf(":%d", port),
		},
		httpClient: &http.Client{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.hello)
	mux.HandleFunc("/.well-known/openid-configuration", s.openidConfiguration)
	mux.HandleFunc("/jwks.json", s.jwks)
	mux.HandleFunc("/gcs/buckets", s.listGCSBuckets)
	mux.HandleFunc("/gcs/buckets-sdk", s.listGCSBucketsBySDK)
	s.server.Handler = mux

	return s
}

func (s *Server) Start(ctx context.Context) error {
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown: %w", err)
	}

	return nil
}

func (s *Server) hello(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello, World!\n")
}

type OpenidConfigurationResponse struct {
	Issuer  string `json:"issuer"`
	JWKsURI string `json:"jwks_uri"`
}

func (s *Server) openidConfiguration(w http.ResponseWriter, r *http.Request) {
	res := &OpenidConfigurationResponse{
		Issuer:  s.env.WorkloadIdentityFederationIssuerURL,
		JWKsURI: fmt.Sprintf("%s/jwks.json", s.env.WorkloadIdentityFederationIssuerURL),
	}
	if err := json.NewEncoder(w).Encode(&res); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type JWKsResponse struct {
	Keys []json.RawMessage `json:"keys"`
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	fmt.Println("some one access!!!!!!!!")
	pubKey, err := jwk.FromRaw(publicKey)
	if err != nil {
		log.Fatalf("failed to create JWK: %v", err)
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyJSON, err := json.Marshal(pubKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	res := &JWKsResponse{
		Keys: []json.RawMessage{keyJSON},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&res); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

//go:embed credentials/service-account.json
var serviceAccountJSON []byte

func (s *Server) listGCSBuckets(w http.ResponseWriter, r *http.Request) {
	token, err := s.getToken()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch token: %v", err), http.StatusInternalServerError)
		return
	}

	client, err := storage.NewClient(r.Context(), option.WithTokenSource(
		oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
			TokenType:   "Bearer",
		}),
	),
		option.WithScopes(storage.ScopeReadOnly))

	// client, err := storage.NewClient(r.Context(), option.WithCredentialsJSON(serviceAccountJSON))
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("Failed to create storage client: %v", err), http.StatusInternalServerError)
	// 	return
	// }
	defer client.Close()

	var buckets []string
	it := client.Buckets(r.Context(), s.env.GoogleCloudProject)
	for {
		bucketAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list buckets: %v", err), http.StatusInternalServerError)
			return
		}
		buckets = append(buckets, bucketAttrs.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string][]string{"buckets": buckets}); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) listGCSBucketsBySDK(w http.ResponseWriter, r *http.Request) {
	creds, err := GetCredentials(s.env.WorkloadIdentityFederationAUD, s.env.WorkloadIdentityFederationIssuerURL, s.env.WorkloadIdentityFederationServiceAccount)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get credentials: %v", err), http.StatusInternalServerError)
		return
	}

	client, err := storage.NewClient(r.Context(), option.WithAuthCredentials(creds))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create storage client: %v", err), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	var buckets []string
	it := client.Buckets(r.Context(), s.env.GoogleCloudProject)
	for {
		bucketAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list buckets: %v", err), http.StatusInternalServerError)
			return
		}
		buckets = append(buckets, bucketAttrs.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string][]string{"buckets": buckets}); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

type subjectTokenProvider struct {
	aud     string
	issuer  string
	subject string
}

func (p *subjectTokenProvider) SubjectToken(ctx context.Context, opts *externalaccount.RequestOptions) (string, error) {
	return generateIDToken(p.aud, p.subject, p.issuer)
}

func GetCredentials(aud, issuer, sub string) (*auth.Credentials, error) {
	tokenProvider := &subjectTokenProvider{
		aud:     aud,
		issuer:  issuer,
		subject: sub,
	}

	opts := &externalaccount.Options{
		Audience:             aud,
		SubjectTokenType:     "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:             "https://sts.googleapis.com/v1/token",
		Scopes:               []string{"https://www.googleapis.com/auth/cloud-platform"},
		SubjectTokenProvider: tokenProvider,
	}

	creds, err := externalaccount.NewCredentials(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials: %v", err)
	}

	return creds, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (s *Server) getToken() (string, error) {
	token, err := generateIDToken(s.env.WorkloadIdentityFederationAUD, s.env.WorkloadIdentityFederationServiceAccount, s.env.WorkloadIdentityFederationIssuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to generate id token: %w", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		log.Printf("Invalid token format")
		return "", fmt.Errorf("Invalid token format")
	}

	googleToken, err := exchangeToken(s.httpClient, s.env.WorkloadIdentityFederationAUD, token)
	if err != nil {
		return "", fmt.Errorf("failed to exchange id token for google cloud access token: %w", err)
	}

	saToken, err := generateServiceAccountToken(s.httpClient, googleToken, s.env.WorkloadIdentityFederationServiceAccount)
	if err != nil {
		return "", fmt.Errorf("failed to get service account token for google cloud access token: %w", err)
	}

	return saToken, nil
}

func generateIDToken(aud, serviceAccount, issuer string) (string, error) {
	token := jwt.New()

	// クレームの設定
	err := token.Set(jwt.AudienceKey, aud)
	if err != nil {
		return "", err
	}

	err = token.Set(jwt.IssuerKey, issuer)
	if err != nil {
		return "", err
	}

	err = token.Set(jwt.SubjectKey, serviceAccount)
	if err != nil {
		return "", err
	}

	err = token.Set(jwt.IssuedAtKey, time.Now())
	if err != nil {
		return "", err
	}

	err = token.Set(jwt.ExpirationKey, time.Now().Add(1*time.Hour))
	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

func exchangeToken(httpClient *http.Client, aud, idToken string) (string, error) {
	body := map[string]string{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"audience":             aud,
		"scope":                "https://www.googleapis.com/auth/cloud-platform",
		"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"subject_token":        idToken,
		"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
	}

	// リクエストの内容をログ
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("STS exchange failed: %s", string(respBody))
	}

	var result struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse STS response: %v", err)
	}

	return result.AccessToken, nil
}

func checkEnvironment() {
	envVars := []string{
		"GOOGLE_CLOUD_PROJECT",
		"GCLOUD_PROJECT",
		"CLOUDSDK_CORE_PROJECT",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"CLOUDSDK_API_ENDPOINT_OVERRIDES_STORAGE",
	}

	for _, env := range envVars {
		if value := os.Getenv(env); value != "" {
			log.Printf("Environment variable %s is set to: %s", env, value)
		}
	}
}

func generateServiceAccountToken(client *http.Client, fedToken, serviceAccount string) (string, error) {
	url := fmt.Sprintf("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
		serviceAccount)

	body := map[string]interface{}{
		"scope":    []string{"https://www.googleapis.com/auth/cloud-platform"},
		"lifetime": "3600s",
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+fedToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"accessToken"`
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to generate access token: HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to new a json decoder: %w", err)
	}

	return result.AccessToken, nil
}

func loadOrCreateKeys() error {
	// File paths for the keys
	privKeyPath := "private.pem"
	pubKeyPath := "public.pem"

	// Try to read the private key
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If the private key does not exist, generate a new one
			fmt.Println("Private key does not exist. Generating a new one.")
			privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return fmt.Errorf("failed to generate private key: %v", err)
			}

			// Save the private key
			privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
			if err != nil {
				return fmt.Errorf("failed to encode private key: %v", err)
			}
			err = os.WriteFile(privKeyPath, privKeyBytes, 0600)
			if err != nil {
				return fmt.Errorf("failed to save private key: %v", err)
			}

			// Save the public key
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to encode public key: %v", err)
			}
			err = os.WriteFile(pubKeyPath, pubKeyBytes, 0644)
			if err != nil {
				return fmt.Errorf("failed to save public key: %v", err)
			}
		} else {
			return fmt.Errorf("failed to read private key: %v", err)
		}
	} else {
		// Parse the private key
		privateKey, err = x509.ParseECPrivateKey(privKeyData)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}
	}

	// Read and parse the public key
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %v", err)
	}
	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}
	var ok bool
	publicKey, ok = pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not of type *ecdsa.PublicKey")
	}

	return nil
}
