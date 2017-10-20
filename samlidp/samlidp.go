package samlidp

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

// New returns a new saml idp Server
func New(key, cert string) (*samlidp.Server, error) {
	logr := logger.DefaultLogger
	flag.Parse()

	gatewayURL := os.Getenv("API_GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	u, err := url.Parse(gatewayURL)
	if err != nil {
		return nil, err
	}

	baseURL, err := url.Parse(fmt.Sprintf("http://%s:8000/saml/idp", u.Hostname()))
	if err != nil {
		return nil, err
	}

	keyPair, err := tls.LoadX509KeyPair(key, cert)
	if err != nil {
		return nil, err
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, err
	}

	metadataURL := *baseURL
	metadataURL.Path = metadataURL.Path + "/metadata"
	ssoURL := *baseURL
	ssoURL.Path = ssoURL.Path + "/sso"

	s := &samlidp.Server{
		IDP: saml.IdentityProvider{
			Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
			Logger:      logr,
			Certificate: keyPair.Leaf,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
		},
	}

	return s, nil
}
