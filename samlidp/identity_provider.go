package samlidp

import (
	"fmt"
	"net/http"
	"regexp"

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

// ValidateCredentials validates the user credential( username/password )
func ValidateCredentials(username, pass string) error {
	if match, _ := regexp.MatchString("^([a-zA-Z0-9@]{4,50})$", username); !match {
		return fmt.Errorf("You have entered invalid user")
	}
	if len(pass) < 6 {
		return fmt.Errorf("You have entered invalid password")
	}
	return nil
}
