package db

import (
	"net/http"
	"os"

	"github.com/Microkubes/backends"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/goadesign/goa"
)

// GetServiceProvider returns the Service Provider metadata for the service provider ID,
// which is typically the service provider's metadata URL. If an appropriate service
// provider cannot be found then the returned error must be os.ErrNotExist.
func (s *IDPStore) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	service := &samlidp.Service{}
	_, err := s.Services.GetOne(backends.NewFilter().Match("name", serviceProviderID), service)
	if err != nil {
		if backends.IsErrNotFound(err) {
			return nil, os.ErrNotExist
		}

		return nil, goa.ErrInternal(err)
	}

	return &service.Metadata, err
}

// AddServiceProvider register new service provider, update if already exists.
func (s *IDPStore) AddServiceProvider(service *samlidp.Service) error {
	var filter backends.Filter
	srv := &samlidp.Service{}
	_, err := s.Services.GetOne(backends.NewFilter().Match("name", service.Name), srv)
	if err != nil {
		if !backends.IsErrNotFound(err) {
			return goa.ErrInternal(err)
		}
	} else {
		// Service exists, make update
		filter = backends.NewFilter().Match("name", service.Name)
	}

	if _, err := s.Services.Save(service, filter); err != nil {
		return goa.ErrInternal(err)
	}

	return nil
}

// DeleteServiceProvider deletes the service by serviceID which is EntityID
func (s *IDPStore) DeleteServiceProvider(serviceID string) error {
	err := s.Services.DeleteOne(backends.NewFilter().Match("name", serviceID))
	if err != nil {
		if backends.IsErrNotFound(err) {
			return goa.ErrNotFound("service not found")
		}

		return goa.ErrInternal(err)
	}

	return nil
}

// GetServiceProviders returns all SP
func (s *IDPStore) GetServiceProviders() (*[]samlidp.Service, error) {
	var services []samlidp.Service
	var typeHint map[string]interface{}

	items, err := s.Services.GetAll(nil, typeHint, "", "", 0, 0)
	if err != nil {
		return nil, goa.ErrInternal(err)
	}

	if err := backends.MapToInterface(items, &services); err != nil {
		return nil, goa.ErrInternal(err)
	}

	if len(services) == 0 {
		return nil, goa.ErrNotFound("no services found!")
	}

	return &services, nil
}
