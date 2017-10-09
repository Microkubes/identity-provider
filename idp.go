package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/JormungandrK/identity-provider/app"
	"github.com/JormungandrK/identity-provider/config"
	"github.com/JormungandrK/identity-provider/db"
	jormungandrSamlIdp "github.com/JormungandrK/identity-provider/samlidp"
	"github.com/JormungandrK/identity-provider/service"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
)

var sessionMaxAge = time.Hour * 24

var badRequestFile = "public/bad-request.html"
var errorFile = "public/error.html"
var loginFile = "public/login/login-form.html"

// IdpController implements the idp resource.
type IdpController struct {
	*goa.Controller
	Repository db.Repository
	IDP        *saml.IdentityProvider
}

type SamlIdentityProvider struct {
	*saml.IdentityProvider
}

// NewIdpController creates a idp controller.
func NewIdpController(service *goa.Service, repository db.Repository, idp *saml.IdentityProvider) *IdpController {
	return &IdpController{
		Controller: service.NewController("IdpController"),
		Repository: repository,
		IDP:        idp,
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

// Metadata runs the getMetadata action.
func (c *IdpController) GetMetadata(ctx *app.GetMetadataIdpContext) error {
	buf, err := xml.MarshalIndent(c.IDP.Metadata(), "", "  ")
	if err != nil {
		return nil
	}
	return ctx.OK(buf)
}

// LoginUser shows login form
func (c *IdpController) LoginUser(ctx *app.LoginUserIdpContext) error {
	r := ctx.Request
	w := ctx.ResponseData
	c.IDP.ServiceProviderProvider = c.Repository

	gatewayURL := os.Getenv("API_GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	req := &saml.IdpAuthnRequest{
		IDP:         c.IDP,
		HTTPRequest: r,
		RelayState:  "relayState",
	}

	jormungandrSamlIdp.LoginForm(w, r, req, fmt.Sprintf("%s/saml/idp/login", gatewayURL), "", loginFile)

	return nil
}

// ServeLoginUser runs login user action
func (c *IdpController) ServeLoginUser(ctx *app.ServeLoginUserIdpContext) error {
	r := ctx.Request
	w := ctx.ResponseData
	c.IDP.ServiceProviderProvider = c.Repository

	gatewayURL := os.Getenv("API_GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	config, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}

	req := &saml.IdpAuthnRequest{
		IDP:         c.IDP,
		HTTPRequest: r,
		RelayState:  "relayState",
	}

	username := strings.TrimSpace(r.FormValue("user"))
	password := strings.TrimSpace(r.FormValue("password"))

	if username == "" || password == "" {
		jormungandrSamlIdp.LoginForm(w, r, req, fmt.Sprintf("%s/saml/idp/login", gatewayURL), "Credentials required!", loginFile)
		return nil
	}

	if err := jormungandrSamlIdp.ValidateCredentials(username, password); err != nil {
		jormungandrSamlIdp.LoginForm(w, r, req, fmt.Sprintf("%s/saml/idp/login", gatewayURL), err.Error(), loginFile)
		return nil
	}

	user, err := service.FindUser(username, password)
	if err != nil {
		jormungandrSamlIdp.LoginForm(w, r, req, fmt.Sprintf("%s/saml/idp/login", gatewayURL), "Wrong username or password!", loginFile)
		return nil
	}

	roles := []string{}
	for _, v := range user["roles"].([]interface{}) {
		roles = append(roles, v.(string))
	}

	encodedPrivatekKey := x509.MarshalPKCS1PrivateKey(c.IDP.Key.(*rsa.PrivateKey))
	claims := jwt.MapClaims{
		"username": user["username"].(string),
		"userId":   user["id"].(string),
		"roles":    roles,
		"email":    user["email"].(string),
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := tokenHS.SignedString(encodedPrivatekKey)
	if err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
	}

	session := &saml.Session{
		ID:            tokenStr,
		CreateTime:    saml.TimeNow(),
		ExpireTime:    saml.TimeNow().Add(sessionMaxAge),
		Index:         hex.EncodeToString(jormungandrSamlIdp.RandomBytes(32)),
		UserName:      user["id"].(string),
		Groups:        roles,
		UserEmail:     user["email"].(string),
		UserGivenName: user["username"].(string),
	}

	if err = c.Repository.AddSession(session); err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
		return nil
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   r.URL.Scheme == "https",
		Path:     "/",
	})

	http.Redirect(w, r, config.Client["redirect-from-login"], http.StatusFound)

	return nil
}

// ServeSSO runs the serveSSO action.
func (c *IdpController) ServeSSO(ctx *app.ServeSSOIdpContext) error {
	r := ctx.Request
	w := ctx.ResponseData
	c.IDP.ServiceProviderProvider = c.Repository

	req, err := jormungandrSamlIdp.ValidateSamlRequest(c.IDP, r)
	if err != nil {
		jormungandrSamlIdp.BadRequestForm(w, r, err.Error(), badRequestFile)
		return nil
	}

	session, _ := c.Repository.GetSession(w, r, req)
	if session == nil {
		jormungandrSamlIdp.LoginForm(w, r, req, req.IDP.SSOURL.String(), "", loginFile)
		return nil
	}

	if err = jormungandrSamlIdp.MakeAssertion(req, c.IDP, session); err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
		return nil
	}

	if err := req.WriteResponse(w); err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
		return nil
	}

	return nil
}

// ServeLogin runs the login action.
func (c *IdpController) ServeLogin(ctx *app.ServeLoginIdpContext) error {
	r := ctx.Request
	w := ctx.ResponseData
	c.IDP.ServiceProviderProvider = c.Repository

	req, err := jormungandrSamlIdp.ValidateSamlRequest(c.IDP, r)
	if err != nil {
		jormungandrSamlIdp.BadRequestForm(w, r, err.Error(), badRequestFile)
		return nil
	}

	username := strings.TrimSpace(r.FormValue("user"))
	password := strings.TrimSpace(r.FormValue("password"))

	if username == "" || password == "" {
		jormungandrSamlIdp.LoginForm(w, r, req, req.IDP.SSOURL.String(), "Credentials required!", loginFile)
		return nil
	}

	if err := jormungandrSamlIdp.ValidateCredentials(username, password); err != nil {
		jormungandrSamlIdp.LoginForm(w, r, req, req.IDP.SSOURL.String(), err.Error(), loginFile)
		return nil
	}

	user, err := service.FindUser(username, password)
	if err != nil {
		jormungandrSamlIdp.LoginForm(w, r, req, req.IDP.SSOURL.String(), "Wrong username or password!", loginFile)
		return nil
	}

	roles := []string{}
	for _, v := range user["roles"].([]interface{}) {
		roles = append(roles, v.(string))
	}

	encodedPrivatekKey := x509.MarshalPKCS1PrivateKey(c.IDP.Key.(*rsa.PrivateKey))
	claims := jwt.MapClaims{
		"username": user["username"].(string),
		"userId":   user["id"].(string),
		"roles":    roles,
		"email":    user["email"].(string),
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := tokenHS.SignedString(encodedPrivatekKey)
	if err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
	}

	session := &saml.Session{
		ID:            tokenStr,
		CreateTime:    saml.TimeNow(),
		ExpireTime:    saml.TimeNow().Add(sessionMaxAge),
		Index:         hex.EncodeToString(jormungandrSamlIdp.RandomBytes(32)),
		UserName:      user["id"].(string),
		Groups:        roles,
		UserEmail:     user["email"].(string),
		UserGivenName: user["username"].(string),
	}

	if err = c.Repository.AddSession(session); err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
		return nil
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.ID,
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   r.URL.Scheme == "https",
		Path:     "/",
	})

	if err = jormungandrSamlIdp.MakeAssertion(req, c.IDP, session); err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
		return nil

	}

	if err := req.WriteResponse(w); err != nil {
		jormungandrSamlIdp.ErrorForm(w, r, fmt.Sprintf("A server error has occured. %s", err.Error()), 500, errorFile)
		return nil
	}

	return nil
}

// AddService runs the add service action.
func (c *IdpController) AddServiceProvider(ctx *app.AddServiceProviderIdpContext) error {
	r := ctx.Request
	service := samlidp.Service{}

	metadata, err := jormungandrSamlIdp.GetSPMetadata(r.Body)
	if err != nil {
		return ctx.BadRequest(err)
	}

	service.Metadata = *metadata
	service.Name = service.Metadata.EntityID

	err = c.Repository.AddServiceProvider(&service)
	if err != nil {
		ctx.InternalServerError(err)
	}

	return ctx.Created()
}

// DeleteServiceProvider runs the delete SP action.
func (c *IdpController) DeleteServiceProvider(ctx *app.DeleteServiceProviderIdpContext) error {
	err := c.Repository.DeleteServiceProvider(ctx.Payload.ServiceID)
	if err != nil {
		e := err.(*goa.ErrorResponse)

		switch e.Status {
		case 404:
			return ctx.NotFound(err)
		default:
			return ctx.InternalServerError(err)
		}
	}

	return ctx.OK([]byte("OK"))
}

// GetServiceProviders runs the get Service Providers action.
func (c *IdpController) GetServiceProviders(ctx *app.GetServiceProvidersIdpContext) error {
	services, err := c.Repository.GetServiceProviders()
	if err != nil {
		e := err.(*goa.ErrorResponse)

		switch e.Status {
		case 404:
			return ctx.NotFound(err)
		default:
			return ctx.InternalServerError(err)
		}
	}

	resp, err := json.Marshal(services)
	if err != nil {
		return ctx.InternalServerError(goa.ErrInternal(err))
	}

	return ctx.OK(resp)
}

// DeleteSession runs the delete session action.
func (c *IdpController) DeleteSession(ctx *app.DeleteSessionIdpContext) error {
	err := c.Repository.DeleteSession(ctx.Payload.SessionID)
	if err != nil {
		e := err.(*goa.ErrorResponse)

		switch e.Status {
		case 404:
			return ctx.NotFound(err)
		default:
			return ctx.InternalServerError(err)
		}
	}

	return ctx.OK([]byte("OK"))
}

// GetSessions runs the get sessions action.
func (c *IdpController) GetSessions(ctx *app.GetSessionsIdpContext) error {
	sessions, err := c.Repository.GetSessions()
	if err != nil {
		e := err.(*goa.ErrorResponse)

		switch e.Status {
		case 404:
			return ctx.NotFound(err)
		default:
			return ctx.InternalServerError(err)
		}
	}

	resp, err := json.Marshal(sessions)
	if err != nil {
		return ctx.InternalServerError(goa.ErrInternal(err))
	}

	return ctx.OK(resp)
}
