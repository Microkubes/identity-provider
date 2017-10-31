package config

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	config := `{
	    "microservice": {
			"name": "identity-provider-microservice",
			"port": 8080,
			"virtual_host": "identity-provider.services.jormugandr.org",
			"hosts": ["localhost", "identity-provider.services.jormugandr.org"],
			"weight": 10,
			"slots": 100
	    },
	   	"gatewayUrl": "http://kong:8000",
	    "gatewayAdminUrl": "http://kong:8001",
	    "services": {
	      	"microservice-user": "http://127.0.0.1:8081/users"
	    },
	   	"client": {
			"redirect-from-login": "http://localhost:8082/profiles/me"
		}
	  }`

	cnfFile, err := ioutil.TempFile("", "tmp-config")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(cnfFile.Name())

	cnfFile.WriteString(config)

	cnfFile.Sync()

	loadedCnf, err := LoadConfig(cnfFile.Name())

	if err != nil {
		t.Fatal(err)
	}

	if loadedCnf == nil {
		t.Fatal("Configuration was not read")
	}
}
