package main

import (
	"context"
	"testing"

	"github.com/JormungandrK/identity-provider/app/test"
	"github.com/goadesign/goa"
)

var (
	service = goa.New("identity-provider")
	ctrl    = NewIdpController(service)
)

// Call generated test helper, this checks that the returned media type is of the
// correct type (i.e. uses view "default") and validates the media type.
// Also, it ckecks the returned status code
func TestGetGoogleMetadataIdpOK(t *testing.T) {
	test.GetGoogleMetadataIdpOK(t, context.Background(), service, ctrl)
}

func Test
