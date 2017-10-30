//go:generate goagen bootstrap -d github.com/JormungandrK/identity-provider/design

package main

import (
	"net/http"
	"os"

	"github.com/JormungandrK/identity-provider/app"
	"github.com/JormungandrK/identity-provider/config"
	"github.com/JormungandrK/identity-provider/db"
	jormungandrSamlIdp "github.com/JormungandrK/identity-provider/samlidp"
	"github.com/JormungandrK/microservice-tools/gateway"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
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

	registration := gateway.NewKongGateway(cfg.GatewayAdminURL, &http.Client{}, &cfg.Microservice)
	err = registration.SelfRegister()
	if err != nil {
		panic(err)
	}

	defer registration.Unregister() // defer the unregister for after main exits

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())

	dbConf := cfg.Database
	// Create new session to MongoDB
	session := db.NewSession(dbConf.Host, dbConf.Username, dbConf.Password, dbConf.DatabaseName)
	// At the end close session
	defer session.Close()

	// Create metadata collection and indexes
	indexServices := []string{"name"}
	metadataCollection := db.PrepareDB(session, dbConf.DatabaseName, "services", indexServices)

	// Create type collection and indexes
	indexSessions := []string{"id"}
	typeCollection := db.PrepareDB(session, dbConf.DatabaseName, "sessions", indexSessions)

	idpServer, err := jormungandrSamlIdp.New("/run/secrets/service.cert", "/run/secrets/service.key", cfg)
	if err != nil {
		service.LogError("Creation of SAML IDP server failed", "err", err)
		return
	}

	// Mount "idp" controller
	c1 := NewIdpController(service, &db.MongoCollections{
		Services: metadataCollection,
		Sessions: typeCollection,
	}, &idpServer.IDP, cfg)
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
