//go:generate goagen bootstrap -d github.com/Microkubes/identity-provider/design

package main

import (
	"os"

	"github.com/Microkubes/identity-provider/app"
	"github.com/Microkubes/identity-provider/config"
	"github.com/Microkubes/identity-provider/db"
	jormungandrSamlIdp "github.com/Microkubes/identity-provider/samlidp"
	"github.com/keitaroinc/goa"
	"github.com/keitaroinc/goa/middleware"
)

func main() {
	// Create service
	service := goa.New("identity-provider")

	cf := os.Getenv("SERVICE_CONFIG_FILE")
	if cf == "" {
		cf = "/run/secrets/microservice_identity_provider_config.json"
	}
	cfg, err := config.LoadConfig(cf)
	if err != nil {
		service.LogError("config", "err", err)
		return
	}

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())

	// Cretae IDP store
	store, cleanup, err := db.NewIDPStore(cfg.Database)
	if err != nil {
		service.LogError("Creation of IDP store failed", "err", err)
		return
	}
	defer cleanup()

	idpServer, err := jormungandrSamlIdp.New(cfg)
	if err != nil {
		service.LogError("Creation of SAML IDP server failed", "err", err)
		return
	}

	// Mount "idp" controller
	c1 := NewIdpController(service, store, &idpServer.IDP, cfg)
	app.MountIdpController(service, c1)
	// Mount "swagger" controller
	c2 := NewSwaggerController(service)
	app.MountSwaggerController(service, c2)
	// Mount "public" controller
	c3 := NewPublicController(service)
	app.MountPublicController(service, c3)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}

}
