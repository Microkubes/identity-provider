package db

import (
	"net/http"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/keitaroinc/goa"
)

type FakeDB struct {
	Name string
}

// GetServiceProvider returns spMetadata for given serviceProviderID which is entityID
func (db *DB) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	rv, ok := db.services[serviceProviderID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return rv, nil
}

// AddServiceProvider adds metadata of the SP
func (db *DB) AddServiceProvider(service *samlidp.Service) error {
	if service.Name == "http://internal-error/saml/metadata" {
		return goa.ErrInternal("Internal Server Error")
	}
	db.services[service.Name] = &service.Metadata
	return nil
}

// DeleteServiceProvider deletes metadata for the given serviceID
func (db *DB) DeleteServiceProvider(serviceID string) error {
	if serviceID == "not-found" {
		return goa.ErrNotFound("service not found")
	}

	if serviceID == "internal-server-error" {
		return goa.ErrInternal("Internal Server Error")
	}

	return nil
}

// GetServiceProviders lists all SP
func (db *DB) GetServiceProviders() (*[]samlidp.Service, error) {
	if _, ok := db.services["not-found"]; ok {
		delete(db.services, "not-found")
		return nil, goa.ErrNotFound("no services found")
	}
	if _, ok := db.services["internal-server-error"]; ok {
		delete(db.services, "internal-server-error")
		return nil, goa.ErrInternal("Internal Server Error")
	}

	var services []samlidp.Service
	var entityDesc *saml.EntityDescriptor

	for key, value := range db.services {
		services = append(services, samlidp.Service{
			Name:     key,
			Metadata: *value,
		})
		entityDesc = value
	}
	db.services["not-found"] = entityDesc
	db.services["internal-server-error"] = entityDesc

	return &services, nil
}
