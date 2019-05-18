package main

import (
	"github.com/keitaroinc/goa"
)

// PublicController implements the public resource.
type PublicController struct {
	*goa.Controller
}

// NewPublicController creates a public controller.
func NewPublicController(service *goa.Service) *PublicController {
	return &PublicController{Controller: service.NewController("PublicController")}
}
