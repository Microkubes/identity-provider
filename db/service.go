package db

import (
	"net/http"
	"os"

	"gopkg.in/mgo.v2/bson"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/goadesign/goa"
)

// GetServiceProvider returns the Service Provider metadata for the service provider ID,
// which is typically the service provider's metadata URL. If an appropriate service
// provider cannot be found then the returned error must be os.ErrNotExist.
func (m *MongoCollections) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	service := &samlidp.Service{}
	query := bson.M{"name": bson.M{"$eq": serviceProviderID}}
	err := m.Services.Find(query).Limit(1).One(service)
	if err != nil {
		if err.Error() == "not found" {
			return nil, os.ErrNotExist
		} else {
			return nil, goa.ErrInternal(err)
		}
	}

	return &service.Metadata, nil
}

// AddServiceProvider register new service provider
func (m *MongoCollections) AddServiceProvider(service *samlidp.Service) error {
	_, err := m.Services.Upsert(
		bson.M{"name": service.Name},
		bson.M{"$set": service})

	if err != nil {
		return goa.ErrInternal(err)
	}

	return nil
}

// DeleteServiceProvider deletes the service by serviceID which is EntityID
func (m *MongoCollections) DeleteServiceProvider(serviceID string) error {
	selector := bson.M{"name": bson.M{"$eq": serviceID}}
	err := m.Services.Remove(selector)
	if err != nil {
		if err.Error() == "not found" {
			return goa.ErrNotFound("service not found")
		} else {
			return goa.ErrInternal(err)
		}
	}

	return nil
}

// GetServiceProviders returns all SP
func (m *MongoCollections) GetServiceProviders() (*[]samlidp.Service, error) {
	var services []samlidp.Service
	if err := m.Services.Find(nil).All(&services); err != nil {
		return nil, goa.ErrInternal(err)
	}

	if len(services) == 0 {
		return nil, goa.ErrNotFound("no services found!")
	}

	return &services, nil
}
