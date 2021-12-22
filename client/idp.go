// Code generated by goagen v1.3.1, DO NOT EDIT.
//
// API "identity provider": idp Resource Client
//
// Command:
// $ goagen
// --design=github.com/Microkubes/identity-provider/design
// --out=$(GOPATH)/src/github.com/Microkubes/identity-provider
// --version=v1.3.1

package client

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// AddServiceProviderIdpPath computes a request path to the addServiceProvider action of idp.
func AddServiceProviderIdpPath() string {

	return fmt.Sprintf("/services")
}

// Add new service provider
func (c *Client) AddServiceProviderIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewAddServiceProviderIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewAddServiceProviderIdpRequest create the request corresponding to the addServiceProvider action endpoint of the idp resource.
func (c *Client) NewAddServiceProviderIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// DeleteServiceProviderIdpPath computes a request path to the deleteServiceProvider action of idp.
func DeleteServiceProviderIdpPath() string {

	return fmt.Sprintf("/services")
}

// Delete a service provider
func (c *Client) DeleteServiceProviderIdp(ctx context.Context, path string, payload *DeleteSPPayload, contentType string) (*http.Response, error) {
	req, err := c.NewDeleteServiceProviderIdpRequest(ctx, path, payload, contentType)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewDeleteServiceProviderIdpRequest create the request corresponding to the deleteServiceProvider action endpoint of the idp resource.
func (c *Client) NewDeleteServiceProviderIdpRequest(ctx context.Context, path string, payload *DeleteSPPayload, contentType string) (*http.Request, error) {
	var body bytes.Buffer
	if contentType == "" {
		contentType = "*/*" // Use default encoder
	}
	err := c.Encoder.Encode(payload, &body, contentType)
	if err != nil {
		return nil, fmt.Errorf("failed to encode body: %s", err)
	}
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("DELETE", u.String(), &body)
	if err != nil {
		return nil, err
	}
	header := req.Header
	if contentType == "*/*" {
		header.Set("Content-Type", "application/json")
	} else {
		header.Set("Content-Type", contentType)
	}
	return req, nil
}

// DeleteSessionIdpPath computes a request path to the deleteSession action of idp.
func DeleteSessionIdpPath() string {

	return fmt.Sprintf("/sessions")
}

// Delete a service provider
func (c *Client) DeleteSessionIdp(ctx context.Context, path string, payload *DeleteSessionPayload, contentType string) (*http.Response, error) {
	req, err := c.NewDeleteSessionIdpRequest(ctx, path, payload, contentType)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewDeleteSessionIdpRequest create the request corresponding to the deleteSession action endpoint of the idp resource.
func (c *Client) NewDeleteSessionIdpRequest(ctx context.Context, path string, payload *DeleteSessionPayload, contentType string) (*http.Request, error) {
	var body bytes.Buffer
	if contentType == "" {
		contentType = "*/*" // Use default encoder
	}
	err := c.Encoder.Encode(payload, &body, contentType)
	if err != nil {
		return nil, fmt.Errorf("failed to encode body: %s", err)
	}
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("DELETE", u.String(), &body)
	if err != nil {
		return nil, err
	}
	header := req.Header
	if contentType == "*/*" {
		header.Set("Content-Type", "application/json")
	} else {
		header.Set("Content-Type", contentType)
	}
	return req, nil
}

// GetGoogleMetadataIdpPath computes a request path to the getGoogleMetadata action of idp.
func GetGoogleMetadataIdpPath() string {

	return fmt.Sprintf("/metadata/google")
}

// Get Google's metadata
func (c *Client) GetGoogleMetadataIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewGetGoogleMetadataIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewGetGoogleMetadataIdpRequest create the request corresponding to the getGoogleMetadata action endpoint of the idp resource.
func (c *Client) NewGetGoogleMetadataIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// GetMetadataIdpPath computes a request path to the getMetadata action of idp.
func GetMetadataIdpPath() string {

	return fmt.Sprintf("/metadata")
}

// Get Jormungandr metadata
func (c *Client) GetMetadataIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewGetMetadataIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewGetMetadataIdpRequest create the request corresponding to the getMetadata action endpoint of the idp resource.
func (c *Client) NewGetMetadataIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// GetServiceProvidersIdpPath computes a request path to the getServiceProviders action of idp.
func GetServiceProvidersIdpPath() string {

	return fmt.Sprintf("/services")
}

// Get all service providres
func (c *Client) GetServiceProvidersIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewGetServiceProvidersIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewGetServiceProvidersIdpRequest create the request corresponding to the getServiceProviders action endpoint of the idp resource.
func (c *Client) NewGetServiceProvidersIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// GetSessionsIdpPath computes a request path to the getSessions action of idp.
func GetSessionsIdpPath() string {

	return fmt.Sprintf("/sessions")
}

// Get all sessions
func (c *Client) GetSessionsIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewGetSessionsIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewGetSessionsIdpRequest create the request corresponding to the getSessions action endpoint of the idp resource.
func (c *Client) NewGetSessionsIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// LoginUserIdpPath computes a request path to the loginUser action of idp.
func LoginUserIdpPath() string {

	return fmt.Sprintf("/login")
}

// Login user
func (c *Client) LoginUserIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewLoginUserIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewLoginUserIdpRequest create the request corresponding to the loginUser action endpoint of the idp resource.
func (c *Client) NewLoginUserIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ServeLoginIdpPath computes a request path to the serveLogin action of idp.
func ServeLoginIdpPath() string {

	return fmt.Sprintf("/sso")
}

// Creare user session
func (c *Client) ServeLoginIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewServeLoginIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewServeLoginIdpRequest create the request corresponding to the serveLogin action endpoint of the idp resource.
func (c *Client) NewServeLoginIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ServeLoginUserIdpPath computes a request path to the serveLoginUser action of idp.
func ServeLoginUserIdpPath() string {

	return fmt.Sprintf("/login")
}

// Login user
func (c *Client) ServeLoginUserIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewServeLoginUserIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewServeLoginUserIdpRequest create the request corresponding to the serveLoginUser action endpoint of the idp resource.
func (c *Client) NewServeLoginUserIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ServeSSOIdpPath computes a request path to the serveSSO action of idp.
func ServeSSOIdpPath() string {

	return fmt.Sprintf("/sso")
}

// Serve Single Sign On
func (c *Client) ServeSSOIdp(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewServeSSOIdpRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewServeSSOIdpRequest create the request corresponding to the serveSSO action endpoint of the idp resource.
func (c *Client) NewServeSSOIdpRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}
