package samlidp

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/JormungandrK/identity-provider/db"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
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

var sessionMaxAge = time.Hour * 24

func createSAMLIdP() (*samlidp.Server, error) {
	logr := logger.DefaultLogger
	flag.Parse()

	gatewayURL := "http://localhost:8080"

	baseURL, err := url.Parse(fmt.Sprintf("%s/saml/idp", gatewayURL))
	if err != nil {
		return nil, err
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

	return s, nil
}

func TestValidateCredentials(t *testing.T) {
	err := ValidateCredentials("test", "test123")
	if err != nil {
		t.Fatal(err)
	}

	err = ValidateCredentials("a#$%", "zz")
	if err == nil {
		t.Fatal("Nil error for invalid username/password")
	}
}

func TestValidateSamlRequest(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=_L5_YvLMqRfj0KX5A62TIKfOHMYVeboixBRg8yYxIwSjp7wmjca2OIRA&SAMLRequest=nJJBj9MwEIX%2FijX3NE7CdlNrE6lshai0QLUtHLhNnCm15NjBMwH236M2i7RwqNBe7XnfvGe%2FO8bBj2Y9ySk80veJWNSvwQc254sGphRMRHZsAg7ERqzZrz88mHKhDTJTEhcDvJCM1zVjihJt9KC2mwZcn73BsqqON93t0tpiRcWqrrRdEna1LYpld2O17vqqrEF9ocQuhgbKhQa1ZZ5oG1gwSAOlLm%2BzQme6OpSFqbQp9GJV1V9BbYjFBZSL8iQymjz30aI%2FRRZT61rnZ9u568ecOYJa%2F0l1HwNPA6U9pR%2FO0ufHhxnA%2FxLKfGJK2Zji0XmacWgZ1O457FsXehe%2BXX%2BZbh5i8%2F5w2GW7T%2FsDtJffMZeoSb2LaUC5DjmfuD47XkYNBXHyBO1%2Fux5IsEfBu%2FzF4va5Ix9xoO1mF72zT68wIwkDOwoCau19%2FHmfCIUakDQR5O288u8mtr8DAAD%2F%2Fw%3D%3D", nil)
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	s.IDP.ServiceProviderProvider = db.New()
	req, err := ValidateSamlRequest(&s.IDP, r)
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("Nil saml request.")
	}

	expiredReq, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ArFTt5M3hUKnjLYPlargEwAyHdO-l6Ckqcukzs7tTPz1xBnTpwnZUg6g&SAMLRequest=nJJBj9MwEIX%2FijX3NK5Tuq21iVS2QlRaoNoWDtwGZ0ItOXbwTID996jNIhUOFeJqz%2FvmPfvdM%2FZhsJtRTvGJvo3Eon72IbI9X9Qw5mgTsmcbsSe24uxh8%2B7Rmpm2yExZfIpwJRlua4acJLkUQO22Nfi2cEjLrlqT65xer3S10Ma45WKuzXq5MK%2BwnVNHHRpQnyizT7EGM9Ogdswj7SILRqnB6PldMdeFXhz1nTWVrapZZarPoLbE4iPKRXkSGWxZhuQwnBKLXemVLs%2B2S98OJXMCtfmd6iFFHnvKB8rfvaOPT48TgP8mmHJkysWQU%2BcDTTh0DGr%2FEva1j62PX2%2B%2FzJdpiO3b43Ff7D8cjtBcfsdeomb1JuUe5TbkfOLboruMWori5Rmaf3bdk2CLgvfl1eLmpSPvsafddp%2BCd8%2F%2FYUYyRvYUBdQmhPTjIRMK1SB5JCibaeWfTWx%2BBQAA%2F%2F8%3D", nil)
	req, err = ValidateSamlRequest(&s.IDP, expiredReq)
	if err == nil {
		t.Fatal("Nil error, expected: request expired at 2017-10-04 07:25:03.323 +0000 UTC")
	}

	badReq, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=_L5_YvLMqRfj0KX5A62TIKfOHMYVeboixBRg8yYxIwSjp7wmjca2OIRA", nil)
	_, err = ValidateSamlRequest(&s.IDP, badReq)
	if err == nil {
		t.Fatal("Nil error, expected: cannot decompress request: unexpected EOF")
	}
}

func TestMakeAssertion(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=_L5_YvLMqRfj0KX5A62TIKfOHMYVeboixBRg8yYxIwSjp7wmjca2OIRA&SAMLRequest=nJJBj9MwEIX%2FijX3NE7CdlNrE6lshai0QLUtHLhNnCm15NjBMwH236M2i7RwqNBe7XnfvGe%2FO8bBj2Y9ySk80veJWNSvwQc254sGphRMRHZsAg7ERqzZrz88mHKhDTJTEhcDvJCM1zVjihJt9KC2mwZcn73BsqqON93t0tpiRcWqrrRdEna1LYpld2O17vqqrEF9ocQuhgbKhQa1ZZ5oG1gwSAOlLm%2BzQme6OpSFqbQp9GJV1V9BbYjFBZSL8iQymjz30aI%2FRRZT61rnZ9u568ecOYJa%2F0l1HwNPA6U9pR%2FO0ufHhxnA%2FxLKfGJK2Zji0XmacWgZ1O457FsXehe%2BXX%2BZbh5i8%2F5w2GW7T%2FsDtJffMZeoSb2LaUC5DjmfuD47XkYNBXHyBO1%2Fux5IsEfBu%2FzF4va5Ix9xoO1mF72zT68wIwkDOwoCau19%2FHmfCIUakDQR5O288u8mtr8DAAD%2F%2Fw%3D%3D", nil)
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	s.IDP.ServiceProviderProvider = db.New()
	req, err := ValidateSamlRequest(&s.IDP, r)
	if err != nil {
		t.Fatal(err)
	}

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

	err = MakeAssertion(req, &s.IDP, session)
	if err != nil {
		t.Fatal(err)
	}
}
