package config

import (
	"encoding/json"
	"io/ioutil"
	"os"

	commonconf "github.com/JormungandrK/microservice-tools/config"
	"github.com/JormungandrK/microservice-tools/gateway"
)

// Config holds the microservice full configuration.
type Config struct {
	// Microservice is a gateway.Microservice configuration for self-registration and service config.
	Microservice gateway.MicroserviceConfig `json:"microservice"`

	// Database holds the database configuration
	Database *commonconf.DBConfig `json:"database"`

	// GatewayURL is the URL of the gateway (proxy).
	GatewayURL string `json:"gatewayUrl"`

	// GatewayAdminURL is the administration URL of the API Gateway. Used for purposes of registration of a
	// microservice with the API gateway.
	GatewayAdminURL string `json:"gatewayAdminUrl"`

	// Services is a map of <service-name>:<service base URL>. For example,
	// "user-microservice": "http://kong.gateway:8001/user"
	Services map[string]string `json:"services"`

	// Client is a map of <client-name>:<url>
	// "redirect-from-login": "http://client-root-url"
	Client map[string]string `json:"client"`
}

// LoadConfig loads a Config from a configuration JSON file.
func LoadConfig(confFile string) (*Config, error) {
	if confFile == "" {
		confFile = os.Getenv("SERVICE_CONFIG_FILE")
		if confFile == "" {
			confFile = "config.json"
		}
	}

	confBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = json.Unmarshal(confBytes, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
