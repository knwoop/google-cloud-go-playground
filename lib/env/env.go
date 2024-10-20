package env

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

type Environments struct {
	GoogleCloudProjectID                     string `envconfig:"GOOGLE_CLOUD_PROJECT_ID" required:"true"`
	GoogleCloudProject                       string `envconfig:"GOOGLE_CLOUD_PROJECT" required:"true"`
	WorkloadIdentityFederationServiceAccount string `envconfig:"WORKLOAD_IDENTITY_FEDERATION_SERVICE_ACCOUNT"`
	WorkloadIdentityFederationIssuerURL      string `envconfig:"WORKLOAD_IDENTITY_FEDERATION_ISSUER_URL"`
	WorkloadIdentityFederationPoolID         string `envconfig:"WORKLOAD_IDENTITY_FEDERATION_POOL_ID"`
	WorkloadIdentityFederationAUD            string `envconfig:"WORKLOAD_IDENTITY_FEDERATION_AUD"`
}

func LoadEnvironments() (*Environments, error) {
	env := new(Environments)
	if err := envconfig.Process("", env); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	return env, nil
}
