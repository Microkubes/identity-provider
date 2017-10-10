package samlidp

import (
	"net/http"

	"github.com/crewjam/saml"
	"github.com/goadesign/goa"
)

// ValidateSamlRequest validates the  SAML requst. If it is not valid error is returned.
func ValidateSamlRequest(idp *saml.IdentityProvider, r *http.Request) (*saml.IdpAuthnRequest, error) {
	req, err := saml.NewIdpAuthnRequest(idp, r)
	if err != nil {
		return nil, goa.ErrInvalidRequest(err)
	}

	if err := req.Validate(); err != nil {
		return nil, goa.ErrInvalidRequest(err)
	}

	return req, nil
}

// MakeAssertion creates the assersion that is returned to the Service Provider
func MakeAssertion(req *saml.IdpAuthnRequest, idp *saml.IdentityProvider, session *saml.Session) error {
	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = saml.DefaultAssertionMaker{}
	}

	assertionMaker.MakeAssertion(req, session)

	return nil
}
