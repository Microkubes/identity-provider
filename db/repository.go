package db

import (
	"net/http"
	"time"

	"gopkg.in/mgo.v2"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
)

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

// MongoCollection wraps a mgo.Collection to embed methods in models.
type MongoCollections struct {
	Services *mgo.Collection
	Sessions *mgo.Collection
}

// NewSession returns a new Mongo Session.
func NewSession(Host string, Username string, Password string, Database string) *mgo.Session {
	session, err := mgo.DialWithInfo(&mgo.DialInfo{
		Addrs:    []string{Host},
		Username: Username,
		Password: Password,
		Database: Database,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	// SetMode - consistency mode for the session.
	session.SetMode(mgo.Monotonic, true)

	return session
}

// PrepareDB ensure presence of persistent and immutable data in the DB.
func PrepareDB(session *mgo.Session, db string, dbCollection string, indexes []string) *mgo.Collection {
	// Create collection
	collection := session.DB(db).C(dbCollection)

	// Define indexes
	for _, elem := range indexes {
		i := []string{elem}
		index := mgo.Index{}
		if dbCollection == "sessions" {
			index.Key = i
			index.Unique = true
			index.Background = true
			index.Sparse = true
			index.ExpireAfter = time.Duration(86400) * time.Second
		} else {
			index.Key = i
			index.Unique = true
			index.Background = true
			index.Sparse = true
		}

		// Create indexes
		if err := collection.EnsureIndex(index); err != nil {
			panic(err)
		}
	}

	return collection
}
