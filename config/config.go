package config

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/JormungandrK/microservice-tools/gateway"
)

// Config holds the microservice full configuration.
type Config struct {
	// Microservice is a gateway.Microservice configuration for self-registration and service config.
	Microservice gateway.MicroserviceConfig `json:"microservice"`
	// Services is a map of <service-name>:<service base URL>. For example,
	// "user-microservice": "http://kong.gateway:8001/user"
	Services map[string]string `json:"services"`
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
