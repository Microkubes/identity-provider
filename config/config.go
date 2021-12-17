package config

import (
	"encoding/json"
	"io/ioutil"
	"os"

	commonconf "github.com/Microkubes/microservice-tools/config"
	"github.com/Microkubes/microservice-tools/gateway"
)

// Config holds the microservice full configuration.
type Config struct {
	// Microservice is a gateway.Microservice configuration for self-registration and service config.
	Microservice gateway.MicroserviceConfig `json:"microservice"`

	// Database holds the database configuration
	Database *commonconf.DBConfig `json:"database"`

	// SystemKey holds the path to the system key which is private RSA key
	SystemKey string `json:"systemKey"`

	// ServiceKey holds the path to the service key
	ServiceKey string `json:"serviceKey"`

	// ServiceCert holds the path to the service cert
	ServiceCert string `json:"serviceCert"`

	// Services is a map of <service-name>:<service base URL>. For example,
	// "user-microservice": "http://kong.gateway:8001/user"
	Services map[string]string `json:"services"`

	// Client is a map of <client-name>:<url>
	// "redirect-from-login": "http://client-root-url"
	Client map[string]string `json:"client"`

	// BaseURL is a <service>:<port> http based URL
	BaseURL string `json:"baseUrl"`
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
