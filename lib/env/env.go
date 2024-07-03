package env

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

type Environments struct {
	GoogleCloudProjectID string `envconfig:"GOOGLE_CLOUD_PROJECT_ID" required:"true"`
}

func LoadEnvironments() (*Environments, error) {
	env := new(Environments)
	if err := envconfig.Process("", env); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	return env, nil
}
