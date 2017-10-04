// Code generated by goagen v1.3.0, DO NOT EDIT.
//
// API "identity provider": Application Media Types
//
// Command:
// $ goagen
// --design=github.com/JormungandrK/identity-provider/design
// --out=$(GOPATH)/src/github.com/JormungandrK/identity-provider
// --version=v1.2.0-dirty

package client

import (
	"github.com/goadesign/goa"
	"net/http"
)

// DecodeErrorResponse decodes the ErrorResponse instance encoded in resp body.
func (c *Client) DecodeErrorResponse(resp *http.Response) (*goa.ErrorResponse, error) {
	var decoded goa.ErrorResponse
	err := c.Decoder.Decode(&decoded, resp.Body, resp.Header.Get("Content-Type"))
	return &decoded, err
}