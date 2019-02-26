package samlidp

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/url"

	"github.com/Microkubes/identity-provider/config"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

// New returns a new saml idp Server
func New(cfg *config.Config) (*samlidp.Server, error) {
	logr := logger.DefaultLogger
	flag.Parse()

	baseURL, err := url.Parse(fmt.Sprintf("%s/saml/idp", cfg.GatewayURL))
	if err != nil {
		return nil, err
	}

	keyPair, err := tls.LoadX509KeyPair(cfg.ServiceCert, cfg.ServiceKey)
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
