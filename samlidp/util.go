package samlidp

import (
	"errors"
	"io/ioutil"

	"encoding/xml"

	"io"

	"github.com/crewjam/saml"
	"github.com/keitaroinc/goa"
)

// RandomBytes generates n random bytes
func RandomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// GetSPMetadata return EntityDescriptor
func GetSPMetadata(r io.Reader) (*saml.EntityDescriptor, error) {
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
