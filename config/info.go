package config

import (
	"fmt"
	"os"
)

type Info struct {
	Port         string
	FQDN         string
	ClientID     string
	ClientSecret string
}

const (
	portEnv         = "PORT"
	clientIdEnv     = "CLIENT_ID"
	clientSecretEnv = "CLIENT_SECRET"
	fqdnEnv         = "FQDN"
)

func New() (*Info, error) {
	port := os.Getenv(portEnv)
	if port == "" {
		return nil, fmt.Errorf("%s environment variable required", portEnv)
	}

	fqdn := os.Getenv(fqdnEnv)
	if fqdn == "" {
		return nil, fmt.Errorf("%s environment variable required", fqdnEnv)
	}

	clientID := os.Getenv(clientIdEnv)
	if clientID == "" {
		return nil, fmt.Errorf("%s environment variable required", clientIdEnv)
	}

	clientSecret := os.Getenv(clientSecretEnv)
	if clientSecret == "" {
		return nil, fmt.Errorf("%s environment variable required", clientSecretEnv)
	}

	return &Info{
		Port:         port,
		FQDN:         fqdn,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}
