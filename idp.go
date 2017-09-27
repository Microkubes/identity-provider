package main

import (
	"io/ioutil"

	"github.com/JormungandrK/identity-provider/app"
	"github.com/JormungandrK/identity-provider/db"
	"github.com/goadesign/goa"
)

// IdpController implements the idp resource.
type IdpController struct {
	*goa.Controller
	Repository db.IDPRepository
}

// NewIdpController creates a idp controller.
func NewIdpController(service *goa.Service, repository db.IDPRepository) *IdpController {
	return &IdpController{
		Controller: service.NewController("IdpController"),
		Repository: repository,
	}
}

// GetGoogleMetadata runs the getGoogleMetadata action.
func (c *IdpController) GetGoogleMetadata(ctx *app.GetGoogleMetadataIdpContext) error {
	dat, err := ioutil.ReadFile("google-metadata.xml")
	if err != nil {
		return err
	}

	return ctx.OK(dat)
}
