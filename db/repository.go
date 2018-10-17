package db

import (
	"net/http"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"

	"github.com/JormungandrK/backends"
	"github.com/Microkubes/microservice-tools/config"
)

// Repository defines interface for accessing DB
type Repository interface {
	// AddSession adds new session in DB
	AddSession(session *saml.Session) error
	// GetSession looks up a Sessions by the session ID.
	GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) (*saml.Session, error)
	// DeleteSession deletes session by sessionID which is cookie value
	DeleteSession(sessionID string) error
	// GetSessions returns all sessions
	GetSessions() (*[]saml.Session, error)

	// AddServiceProvider register new service provider
	AddServiceProvider(service *samlidp.Service) error
	// GetServiceProvider returns the Service Provider metadata for the service provider IDs
	GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error)
	// DeleteServiceProvider deletes the service by serviceID which is EntityID
	DeleteServiceProvider(serviceID string) error
	// GetServiceProviders returns all SP
	GetServiceProviders() (*[]samlidp.Service, error)
}

// IDPStore represents the IDP store containing the Services and Sessions repositories
type IDPStore struct {
	Services backends.Repository
	Sessions backends.Repository
}

// NewIDPStore creates IDP's repositories
func NewIDPStore(cfg *config.DBConfig) (store Repository, cleanup func(), err error) {
	manager := backends.NewBackendSupport(map[string]*config.DBInfo{
		"mongodb":  &cfg.DBInfo,
		"dynamodb": &cfg.DBInfo,
	})

	noop := func() {}
	backend, err := manager.GetBackend(cfg.DBName)
	if err != nil {
		return nil, noop, err
	}

	cleanup = func() {
		backend.Shutdown()
	}

	services, err := backend.DefineRepository("services", backends.RepositoryDefinitionMap{
		"name": "services",
		"indexes": []backends.Index{
			backends.NewUniqueIndex("id"),
			backends.NewUniqueIndex("name"),
		},
		"hashKey":       "id",
		"rangeKey":      "name",
		"readCapacity":  5, // FIXME: read these from config
		"writeCapacity": 5, // FIXME: read these from config
		"GSI": map[string]interface{}{
			"name": map[string]interface{}{
				"readCapacity":  1,
				"writeCapacity": 1,
			},
		},
	})
	if err != nil {
		return nil, noop, err
	}

	sessions, err := backend.DefineRepository("sessions", backends.RepositoryDefinitionMap{
		"name": "sessions",
		"indexes": []backends.Index{
			backends.NewUniqueIndex("id"),
		},
		"hashKey":       "id",
		"readCapacity":  5, // FIXME: read these from config
		"writeCapacity": 5, // FIXME: read these from config
		"GSI": map[string]interface{}{
			"name": map[string]interface{}{
				"readCapacity":  1,
				"writeCapacity": 1,
			},
		},
	})

	return &IDPStore{
		Services: services,
		Sessions: sessions,
	}, cleanup, err
}
