package jwt

import (
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func GenerateJWT() {
	token := jwt.New()
	token.Set(jwt.IssuerKey, "foo")
	token.Set(jwt.SubjectKey, "sub")
	token.Set(jwt.AudienceKey, "https://example.com")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	token.Set("some", "custom_claim")

	signed, err := jwt.Sign(token, jwa.RS256)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}
}
