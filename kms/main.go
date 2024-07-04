package main

import (
	"context"
	"fmt"
	"log"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/knwoop/google-cloud-go-playground/lib/env"
	"google.golang.org/api/iterator"
)

func main() {
	e, err := env.LoadEnvironments()
	if err != nil {
		log.Fatalf("Failed to load environments: %v", err)
	}

	// Location in which to list key rings.
	locationID := "global"
	keyRingID := "jwt-key-ring"
	keyID := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("failed to setup client: %v", err)
	}
	defer client.Close()

	keyRingName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", e.GoogleCloudProjectID, locationID, keyRingID)

	// Create a key ring
	_, err = client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    fmt.Sprintf("projects/%s/locations/%s", e.GoogleCloudProjectID, locationID),
		KeyRingId: keyRingID,
	})
	if err != nil {
		log.Fatalf("failed to create key ring: %v", err)
	}

	purpose := kmspb.CryptoKey_ASYMMETRIC_SIGN
	algorithm := kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	cryptoKey := &kmspb.CryptoKey{
		Purpose: purpose,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			Algorithm: algorithm,
		},
	}

	// 鍵のフルパス
	cryptoKeyName := fmt.Sprintf("%s/cryptoKeys/%s", keyRingName, keyID)

	// 鍵を作成
	_, err = client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: keyID,
		CryptoKey:   cryptoKey,
	})
	if err != nil {
		log.Fatalf("failed to create crypto key: %v", err)
	}

	fmt.Println("Crypto key created:", cryptoKeyName)

	// Create the request to list KeyRings.
	listKeyRingsReq := &kmspb.ListKeyRingsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", e.GoogleCloudProjectID, locationID),
	}

	// List the KeyRings.
	it := client.ListKeyRings(ctx, listKeyRingsReq)

	// Iterate and print the results.
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to list key rings: %v", err)
		}

		fmt.Printf("key ring: %s\n", resp.Name)
	}
}
