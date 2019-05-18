package db

import (
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/keitaroinc/goa"
)

const spMetadata = "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://localhost:8082/user-profile/saml/metadata\" validUntil=\"2025-12-03T01:57:09Z\"><SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"0001-01-01T00:00:00Z\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\"><KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use=\"encryption\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</X509Certificate></X509Data></KeyInfo><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"></EncryptionMethod><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"></EncryptionMethod></KeyDescriptor><AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://localhost:8082/user-profile/saml/acs\" index=\"1\"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>"

var sessionMaxAge = time.Hour * 24

// DB emulates a database driver using in-memory data structures.
type DB struct {
	sync.Mutex
	sessions map[string]*saml.Session
	services map[string]*saml.EntityDescriptor
}

// New initializes a new "DB" with dummy data.
func New() *DB {
	session := &saml.Session{
		ID:            "K7nAHhSfcJzOfqkB6kSWiSJWCh6jroIX9FrxZt6inuU=",
		CreateTime:    saml.TimeNow(),
		ExpireTime:    saml.TimeNow().Add(sessionMaxAge),
		Index:         "2f5eefac59e6fa6b24a078e4f8da1e48441ec3afc25222e00ac127a4ab1db1ed",
		UserName:      "59ce17c60000000000000000",
		Groups:        []string{"user"},
		UserEmail:     "example@host.com",
		UserGivenName: "john",
	}

	entityDesc, _ := getSPMetadata(strings.NewReader(spMetadata))

	return &DB{
		sessions: map[string]*saml.Session{"K7nAHhSfcJzOfqkB6kSWiSJWCh6jroIX9FrxZt6inuU=": session},
		services: map[string]*saml.EntityDescriptor{"https://localhost:8082/user-profile/saml/metadata": entityDesc},
	}
}

// getSPMetadata is a helper method that return SP metadata
func getSPMetadata(r io.Reader) (*saml.EntityDescriptor, error) {
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, goa.ErrBadRequest(err)
	}

	spMetadata := &saml.EntityDescriptor{}

	if err := xml.Unmarshal(bytes, &spMetadata); err != nil {
		if err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}

			if err := xml.Unmarshal(bytes, &entities); err != nil {
				return nil, goa.ErrBadRequest(err)
			}

			for _, e := range entities.EntityDescriptors {
				if len(e.SPSSODescriptors) > 0 {
					return &e, nil
				}
			}

			// there were no SPSSODescriptors in the response
			return nil, errors.New("metadata contained no service provider metadata")
		}

		return nil, goa.ErrBadRequest(err)
	}

	return spMetadata, nil
}
