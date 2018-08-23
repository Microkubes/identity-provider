package db

import (
	"net/http"
	// "os"

	// "gopkg.in/mgo.v2/bson"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	// "github.com/goadesign/goa"
	backends "github.com/JormungandrK/backends"
	"fmt"
)


// GetServiceProvider returns the Service Provider metadata for the service provider ID,
// which is typically the service provider's metadata URL. If an appropriate service
// provider cannot be found then the returned error must be os.ErrNotExist.
func (m *BackendIdentityProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	// service := &samlidp.Service{}
	// query := bson.M{"name": bson.M{"$eq": serviceProviderID}}
	// err := m.Services.Find(query).Limit(1).One(service)
	// if err != nil {
	// 	if err.Error() == "not found" {
	// 		return nil, os.ErrNotExist
	// 	} else {
	// 		return nil, goa.ErrInternal(err)
	// 	}
	// }

	// return &service.Metadata, nil
	return nil, nil
}

// AddServiceProvider register new service provider
func (m *BackendIdentityProvider) AddServiceProvider(service *samlidp.Service) error {
	addService := samlidp.Service {
		Name: service.Name,
		Set: service,
	}

	result, err := m.identityRepository.Save(addService, nil)

	if err != nil {
		return err
	}
	return nil
}

// DeleteServiceProvider deletes the service by serviceID which is EntityID
func (m *BackendIdentityProvider) DeleteServiceProvider(serviceID string) error {
	err := m.identityRepository.DeleteOne(backends.NewFilter().Match("id", serviceID))
	if err != nil {
		return err
	}
	return err
}

// GetServiceProviders returns all SP
func (m *BackendIdentityProvider) GetServiceProviders() (*[]samlidp.Service, error) {
	// var services []samlidp.Service
	// if err := m.Services.Find(nil).All(&services); err != nil {
	// 	return nil, goa.ErrInternal(err)
	// }

	// if len(services) == 0 {
	// 	return nil, goa.ErrNotFound("no services found!")
	// }

	// return &services, nil
	var services []samlidp.Service 
	if err := m.identityRepository.GetAll(&services); err != nil {
		return nil, err
	}

	if len(services) == 0 {
		return nil, err

		fmt.Println("no services found")
	}

	return &services, nil
}
