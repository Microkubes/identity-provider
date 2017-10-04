package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"gopkg.in/h2non/gock.v1"

	"github.com/JormungandrK/identity-provider/app"
	"github.com/JormungandrK/identity-provider/app/test"
	"github.com/JormungandrK/identity-provider/db"
	jormungandrTest "github.com/JormungandrK/identity-provider/test"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
	"github.com/crewjam/saml/samlsp"
	"github.com/goadesign/goa"
)

var (
	goaService = goa.New("identity-provider")
	repository = db.New()
	samlServer = createSAMLIdP()
	ctrl       = NewIdpController(goaService, repository, &samlServer.IDP)
)

var key = func() crypto.PrivateKey {
	b, _ := pem.Decode([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0OhbMuizgtbFOfwbK7aURuXhZx6VRuAs3nNibiuifwCGz6u9
yy7bOR0P+zqN0YkjxaokqFgra7rXKCdeABmoLqCC0U+cGmLNwPOOA0PaD5q5xKhQ
4Me3rt/R9C4Ca6k3/OnkxnKwnogcsmdgs2l8liT3qVHP04Oc7Uymq2v09bGb6nPu
fOrkXS9F6mSClxHG/q59AGOWsXK1xzIRV1eu8W2SNdyeFVU1JHiQe444xLoPul5t
InWasKayFsPlJfWNc8EoU8COjNhfo/GovFTHVjh9oUR/gwEFVwifIHihRE0Hazn2
EQSLaOr2LM0TsRsQroFjmwSGgI+X2bfbMTqWOQIDAQABAoIBAFWZwDTeESBdrLcT
zHZe++cJLxE4AObn2LrWANEv5AeySYsyzjRBYObIN9IzrgTb8uJ900N/zVr5VkxH
xUa5PKbOcowd2NMfBTw5EEnaNbILLm+coHdanrNzVu59I9TFpAFoPavrNt/e2hNo
NMGPSdOkFi81LLl4xoadz/WR6O/7N2famM+0u7C2uBe+TrVwHyuqboYoidJDhO8M
w4WlY9QgAUhkPyzZqrl+VfF1aDTGVf4LJgaVevfFCas8Ws6DQX5q4QdIoV6/0vXi
B1M+aTnWjHuiIzjBMWhcYW2+I5zfwNWRXaxdlrYXRukGSdnyO+DH/FhHePJgmlkj
NInADDkCgYEA6MEQFOFSCc/ELXYWgStsrtIlJUcsLdLBsy1ocyQa2lkVUw58TouW
RciE6TjW9rp31pfQUnO2l6zOUC6LT9Jvlb9PSsyW+rvjtKB5PjJI6W0hjX41wEO6
fshFELMJd9W+Ezao2AsP2hZJ8McCF8no9e00+G4xTAyxHsNI2AFTCQcCgYEA5cWZ
JwNb4t7YeEajPt9xuYNUOQpjvQn1aGOV7KcwTx5ELP/Hzi723BxHs7GSdrLkkDmi
Gpb+mfL4wxCt0fK0i8GFQsRn5eusyq9hLqP/bmjpHoXe/1uajFbE1fZQR+2LX05N
3ATlKaH2hdfCJedFa4wf43+cl6Yhp6ZA0Yet1r8CgYEAwiu1j8W9G+RRA5/8/DtO
yrUTOfsbFws4fpLGDTA0mq0whf6Soy/96C90+d9qLaC3srUpnG9eB0CpSOjbXXbv
kdxseLkexwOR3bD2FHX8r4dUM2bzznZyEaxfOaQypN8SV5ME3l60Fbr8ajqLO288
wlTmGM5Mn+YCqOg/T7wjGmcCgYBpzNfdl/VafOROVbBbhgXWtzsz3K3aYNiIjbp+
MunStIwN8GUvcn6nEbqOaoiXcX4/TtpuxfJMLw4OvAJdtxUdeSmEee2heCijV6g3
ErrOOy6EqH3rNWHvlxChuP50cFQJuYOueO6QggyCyruSOnDDuc0BM0SGq6+5g5s7
H++S/wKBgQDIkqBtFr9UEf8d6JpkxS0RXDlhSMjkXmkQeKGFzdoJcYVFIwq8jTNB
nJrVIGs3GcBkqGic+i7rTO1YPkquv4dUuiIn+vKZVoO6b54f+oPBXd4S0BnuEqFE
rdKNuCZhiaE2XD9L/O9KP1fh5bfEcKwazQ23EvpJHBMm8BGC+/YZNw==
-----END RSA PRIVATE KEY-----`))
	k, _ := x509.ParsePKCS1PrivateKey(b.Bytes)
	return k
}()

var cert = func() *x509.Certificate {
	b, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJAPr/Mrlc8EGhMA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNV
BAMMD3d3dy5leGFtcGxlLmNvbTAeFw0xNTEyMjgxOTE5NDVaFw0yNTEyMjUxOTE5
NDVaMBoxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANDoWzLos4LWxTn8Gyu2lEbl4WcelUbgLN5zYm4ron8A
hs+rvcsu2zkdD/s6jdGJI8WqJKhYK2u61ygnXgAZqC6ggtFPnBpizcDzjgND2g+a
ucSoUODHt67f0fQuAmupN/zp5MZysJ6IHLJnYLNpfJYk96lRz9ODnO1Mpqtr9PWx
m+pz7nzq5F0vRepkgpcRxv6ufQBjlrFytccyEVdXrvFtkjXcnhVVNSR4kHuOOMS6
D7pebSJ1mrCmshbD5SX1jXPBKFPAjozYX6PxqLxUx1Y4faFEf4MBBVcInyB4oURN
B2s59hEEi2jq9izNE7EbEK6BY5sEhoCPl9m32zE6ljkCAwEAAaNQME4wHQYDVR0O
BBYEFB9ZklC1Ork2zl56zg08ei7ss/+iMB8GA1UdIwQYMBaAFB9ZklC1Ork2zl56
zg08ei7ss/+iMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAAVoTSQ5
pAirw8OR9FZ1bRSuTDhY9uxzl/OL7lUmsv2cMNeCB3BRZqm3mFt+cwN8GsH6f3uv
NONIhgFpTGN5LEcXQz89zJEzB+qaHqmbFpHQl/sx2B8ezNgT/882H2IH00dXESEf
y/+1gHg2pxjGnhRBN6el/gSaDiySIMKbilDrffuvxiCfbpPN0NRRiPJhd2ay9KuL
/RxQRl1gl9cHaWiouWWba1bSBb2ZPhv2rPMUsFo98ntkGCObDX6Y1SpkqmoTbrsb
GFsTG2DLxnvr4GdN1BSr0Uu/KV3adj47WkXVPeMYQti/bQmxQB8tRFhrw80qakTL
UzreO96WzlBBMtY=
-----END CERTIFICATE-----`))
	c, _ := x509.ParseCertificate(b.Bytes)
	return c
}()

var rootURL, _ = url.Parse("http://localhost:8081")
var rootURLInternalError, _ = url.Parse("http://internal-error")
var idpMetadataURL, _ = url.Parse("https://www.testshib.org/metadata/testshib-providers.xml")
var samlSP, _ = samlsp.New(samlsp.Options{
	IDPMetadataURL: idpMetadataURL,
	URL:            *rootURL,
	Key:            key.(*rsa.PrivateKey),
	Certificate:    cert,
})

var samlSPErrInternal, _ = samlsp.New(samlsp.Options{
	IDPMetadataURL: idpMetadataURL,
	URL:            *rootURLInternalError,
	Key:            key.(*rsa.PrivateKey),
	Certificate:    cert,
})

func createSAMLIdP() *samlidp.Server {
	logr := logger.DefaultLogger
	flag.Parse()

	gatewayURL := "http://localhost:8080"

	baseURL, err := url.Parse(fmt.Sprintf("%s/saml/idp", gatewayURL))
	if err != nil {
		panic(err)
	}

	metadataURL := *baseURL
	metadataURL.Path = metadataURL.Path + "/metadata"
	ssoURL := *baseURL
	ssoURL.Path = ssoURL.Path + "/sso"

	s := &samlidp.Server{
		IDP: saml.IdentityProvider{
			Key:         key,
			Logger:      logr,
			Certificate: cert,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
		},
	}

	return s
}

// Call generated test helper, this checks that the returned media type is of the
// correct type (i.e. uses view "default") and validates the media type.
// Also, it ckecks the returned status code
func TestGetGoogleMetadataIdpOK(t *testing.T) {
	test.GetGoogleMetadataIdpOK(t, context.Background(), goaService, ctrl)
}

func TestGetMetadata(t *testing.T) {
	test.GetMetadataIdpOK(t, context.Background(), goaService, ctrl)
}

func TestAddServiceProviderIdpCreated(t *testing.T) {
	payload, err := xml.MarshalIndent(samlSP.ServiceProvider.Metadata(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	jormungandrTest.AddServiceProviderIdpCreated(t, context.Background(), goaService, ctrl, payload)
}

func TestAddServiceProviderIdpBadRequest(t *testing.T) {
	payload := []byte("")
	_, err := jormungandrTest.AddServiceProviderIdpBadRequest(t, context.Background(), goaService, ctrl, payload)
	if err == nil {
		t.Fatal("Nill error: AddServiceProviderIdpBadRequest")
	}
}

func TestAddServiceProviderIdpInternalServerError(t *testing.T) {
	payload, err := xml.MarshalIndent(samlSPErrInternal.ServiceProvider.Metadata(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	jormungandrTest.AddServiceProviderIdpInternalServerError(t, context.Background(), goaService, ctrl, payload)
}

func TestDeleteServiceProviderIdpOK(t *testing.T) {
	payload := &app.DeleteSPPayload{
		ServiceID: "https://localhost:8082/user-profile/saml/metadata",
	}

	test.DeleteServiceProviderIdpOK(t, context.Background(), goaService, ctrl, payload)
}

func TestDeleteServiceProviderIdpNotFound(t *testing.T) {
	payload := &app.DeleteSPPayload{
		ServiceID: "not-found",
	}
	test.DeleteServiceProviderIdpNotFound(t, context.Background(), goaService, ctrl, payload)
}

func TestDeleteServiceProviderIdpInternalServerError(t *testing.T) {
	payload := &app.DeleteSPPayload{
		ServiceID: "internal-server-error",
	}
	test.DeleteServiceProviderIdpInternalServerError(t, context.Background(), goaService, ctrl, payload)
}

func TestGetServiceProvidersIdpOK(t *testing.T) {
	test.GetServiceProvidersIdpOK(t, context.Background(), goaService, ctrl)
}

func TestGetServiceProvidersIdpNotFound(t *testing.T) {
	test.GetServiceProvidersIdpNotFound(t, context.Background(), goaService, ctrl)
}

func TestGetServiceProvidersIdpInternalServerError(t *testing.T) {
	test.GetServiceProvidersIdpInternalServerError(t, context.Background(), goaService, ctrl)
}

func TestDeleteSessionIdpOK(t *testing.T) {
	payload := &app.DeleteSessionPayload{
		SessionID: "K7nAHhSfcJzOfqkB6kSWiSJWCh6jroIX9FrxZt6inuU=",
	}
	test.DeleteSessionIdpOK(t, context.Background(), goaService, ctrl, payload)
}

func TestDeleteSessionIdpNotFound(t *testing.T) {
	payload := &app.DeleteSessionPayload{
		SessionID: "not-found",
	}
	test.DeleteSessionIdpNotFound(t, context.Background(), goaService, ctrl, payload)
}

func TestDeleteSessionIdpInternalServerError(t *testing.T) {
	payload := &app.DeleteSessionPayload{
		SessionID: "internal-server-error",
	}
	test.DeleteSessionIdpInternalServerError(t, context.Background(), goaService, ctrl, payload)
}

func TestGetSessionsIdpOK(t *testing.T) {
	test.GetSessionsIdpOK(t, context.Background(), goaService, ctrl)
}

func TestGetSessionsIdpNotFound(t *testing.T) {
	test.GetSessionsIdpNotFound(t, context.Background(), goaService, ctrl)
}

func TestGetSessionsIdpInternalServerError(t *testing.T) {
	test.GetSessionsIdpInternalServerError(t, context.Background(), goaService, ctrl)
}

func TestServeSSO(t *testing.T) {
	req, err := http.NewRequest("GET", "http://localhost:8080/saml/idp/sso?RelayState=_L5_YvLMqRfj0KX5A62TIKfOHMYVeboixBRg8yYxIwSjp7wmjca2OIRA&SAMLRequest=nJJBj9MwEIX%2FijX3NE7CdlNrE6lshai0QLUtHLhNnCm15NjBMwH236M2i7RwqNBe7XnfvGe%2FO8bBj2Y9ySk80veJWNSvwQc254sGphRMRHZsAg7ERqzZrz88mHKhDTJTEhcDvJCM1zVjihJt9KC2mwZcn73BsqqON93t0tpiRcWqrrRdEna1LYpld2O17vqqrEF9ocQuhgbKhQa1ZZ5oG1gwSAOlLm%2BzQme6OpSFqbQp9GJV1V9BbYjFBZSL8iQymjz30aI%2FRRZT61rnZ9u568ecOYJa%2F0l1HwNPA6U9pR%2FO0ufHhxnA%2FxLKfGJK2Zji0XmacWgZ1O457FsXehe%2BXX%2BZbh5i8%2F5w2GW7T%2FsDtJffMZeoSb2LaUC5DjmfuD47XkYNBXHyBO1%2Fux5IsEfBu%2FzF4va5Ix9xoO1mF72zT68wIwkDOwoCau19%2FHmfCIUakDQR5O288u8mtr8DAAD%2F%2Fw%3D%3D", nil)
	if err != nil {
		t.Fatal(err)
	}

	id := "K7nAHhSfcJzOfqkB6kSWiSJWCh6jroIX9FrxZt6inuU="
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{"session", id, "/", "www.example.com", expire, expire.Format(time.UnixDate), 86400, true, true, "test=tcookie", []string{"test=tcookie"}}
	req.AddCookie(&cookie)

	ctx := context.Background()
	prms := url.Values{}
	rw := httptest.NewRecorder()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "IdpTest"), rw, req, prms)

	serveSSOCtx, err := app.NewServeSSOIdpContext(goaCtx, req, goaService)
	if err != nil {
		t.Fatal(err)
	}

	ctrl.ServeSSO(serveSSOCtx)
}

func TestServeLogin(t *testing.T) {
	config := []byte(`{
	    "services": {
	    	"microservice-user": "http://127.0.0.1:8081/users"
	    }
	  }`)

	err := ioutil.WriteFile("config.json", config, 0644)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove("config.json")

	gock.New("http://127.0.0.1:8081").
		Post("/users").
		Reply(200).
		JSON(map[string]interface{}{
			"id":         "59804b3c0000000000000000",
			"fullname":   "Jon Smith",
			"username":   "jon",
			"email":      "jon@test.com",
			"externalId": "qwe04b3c000000qwertydgfsd",
			"roles":      []string{"admin", "user"},
			"active":     false,
		})

	req, err := http.NewRequest("GET", "http://localhost:8080/saml/idp/sso?user=test&password=test123&RelayState=_L5_YvLMqRfj0KX5A62TIKfOHMYVeboixBRg8yYxIwSjp7wmjca2OIRA&SAMLRequest=nJJBj9MwEIX%2FijX3NE7CdlNrE6lshai0QLUtHLhNnCm15NjBMwH236M2i7RwqNBe7XnfvGe%2FO8bBj2Y9ySk80veJWNSvwQc254sGphRMRHZsAg7ERqzZrz88mHKhDTJTEhcDvJCM1zVjihJt9KC2mwZcn73BsqqON93t0tpiRcWqrrRdEna1LYpld2O17vqqrEF9ocQuhgbKhQa1ZZ5oG1gwSAOlLm%2BzQme6OpSFqbQp9GJV1V9BbYjFBZSL8iQymjz30aI%2FRRZT61rnZ9u568ecOYJa%2F0l1HwNPA6U9pR%2FO0ufHhxnA%2FxLKfGJK2Zji0XmacWgZ1O457FsXehe%2BXX%2BZbh5i8%2F5w2GW7T%2FsDtJffMZeoSb2LaUC5DjmfuD47XkYNBXHyBO1%2Fux5IsEfBu%2FzF4va5Ix9xoO1mF72zT68wIwkDOwoCau19%2FHmfCIUakDQR5O288u8mtr8DAAD%2F%2Fw%3D%3D", nil)
	if err != nil {
		t.Fatal(err)
	}

	id := "K7nAHhSfcJzOfqkB6kSWiSJWCh6jroIX9FrxZt6inuU="
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{"session", id, "/", "www.example.com", expire, expire.Format(time.UnixDate), 86400, true, true, "test=tcookie", []string{"test=tcookie"}}
	req.AddCookie(&cookie)

	ctx := context.Background()
	prms := url.Values{}
	rw := httptest.NewRecorder()
	goaCtx := goa.NewContext(goa.WithAction(ctx, "IdpTest"), rw, req, prms)

	serveSSOCtx, err := app.NewServeLoginIdpContext(goaCtx, req, goaService)
	if err != nil {
		t.Fatal(err)
	}

	ctrl.ServeLogin(serveSSOCtx)
}
