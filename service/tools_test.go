package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

	"github.com/Microkubes/identity-provider/config"
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

var confBytes = []byte(`{
	"microservice":	{
		"name": "identity-provider-microservice",
		"port": 8080,
		"paths": ["/saml"],
		"virtual_host": "identity-provider.services.jormungandr.org",
		"weight": 10,
		"slots": 100
	},
	"gatewayUrl": "http://kong:8000",
    "gatewayAdminUrl": "http://kong:8001",
    "systemKey": "system",
 	"services": {
		"microservice-user": "http://kong:8000/users"
	},
	"client": {
		"redirect-from-login": "https://kong:8000/profiles/me"
	},
	"database":{
		"host": "mongo:27017",
		"database": "identity-provider",
		"user": "restapi",
		"pass": "restapi"
	}
}`)

var cfg = &config.Config{}
var _ = json.Unmarshal(confBytes, cfg)

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

func TestFindUser(t *testing.T) {
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{
	    "services": {
	    	"microservice-user": "http://127.0.0.1:8081/users"
	    }
	  }`)

	err = ioutil.WriteFile("config.json", config, 0644)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove("config.json")

	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privateBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytes,
	})
	ioutil.WriteFile("system", privateBytes, 0644)

	defer os.Remove("system")

	gock.New(cfg.Services["microservice-user"]).
		Post("/find").
		Reply(200).
		JSON(map[string]interface{}{
			"id":         "59804b3c0000000000000000",
			"fullname":   "Jon Smith",
			"email":      "jon@test.com",
			"externalId": "qwe04b3c000000qwertydgfsd",
			"roles":      []string{"admin", "user"},
			"active":     true,
		})

	user, err := FindUser("jon", "qwerty123", &s.IDP, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("Nil user")
	}
}

func TestFindUserBadConfig(t *testing.T) {
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{
	    "services": {
	    	"microservice-user": "http://127.0.0.1:8081/not-exists"
	    }
	  }`)

	err = ioutil.WriteFile("config.json", config, 0644)
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
			"email":      "jon@test.com",
			"externalId": "qwe04b3c000000qwertydgfsd",
			"roles":      []string{"admin", "user"},
			"active":     false,
		})

	_, err = FindUser("jon", "qwerty123", &s.IDP, cfg)
	if err == nil {
		t.Fatal("Nil error, expected: Post http://127.0.0.1:8081/not-exists/find: gock: cannot match any request")
	}
}

func TestFindUserBadStatusCode(t *testing.T) {
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	config := []byte(`{
	    "services": {
	    	"microservice-user": "http://127.0.0.1:8082/users/bad-status-code"
	    }
	  }`)

	err = ioutil.WriteFile("config.json", config, 0644)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove("config.json")

	gock.New("http://127.0.0.1:8082").
		Post("/users/bad-status-code").
		Reply(500).
		JSON(map[string]interface{}{
			"details": "Internal Server Error",
		})

	_, err = FindUser("jon", "qwerty123", &s.IDP, cfg)

	if err == nil {
		t.Fatal("Nil error, expected: Internal Server Error")
	}
}

func TestValidateCredentials(t *testing.T) {
	err := validateCredentials("test@example.org", "test123")
	if err != nil {
		t.Fatal(err)
	}

	err = validateCredentials("a#$%", "zz")
	if err == nil {
		t.Fatal("Nil error for invalid email/password")
	}
}

func TestCheckUserCredentials(t *testing.T) {
	r, _ := http.NewRequest("POST", "https://idp.example.com/saml/sso?email=test@example.org&password=test123", nil)
	w := httptest.NewRecorder()
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	req := &saml.IdpAuthnRequest{
		IDP:         &s.IDP,
		HTTPRequest: r,
		RelayState:  "relayState",
	}

	email, password, err := CheckUserCredentials(r, w, req)
	if err != nil {
		t.Fatal(err)
	}
	if email != "test@example.org" {
		t.Fatalf("Expected user name was %s, got %s", "test", email)
	}
	if password != "test123" {
		t.Fatalf("Expected password was %s, got %s", "test123", password)
	}
}

func TestCheckUserCredentialsMissedCredentials(t *testing.T) {
	r, _ := http.NewRequest("POST", "https://idp.example.com/saml/sso", nil)
	w := httptest.NewRecorder()
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	req := &saml.IdpAuthnRequest{
		IDP:         &s.IDP,
		HTTPRequest: r,
		RelayState:  "relayState",
	}

	_, _, err = CheckUserCredentials(r, w, req)
	if err == nil {
		t.Fatal("Nil err, expected :'Credentials required!'")
	}
}

func TestCheckUserCredentialsBadCredentials(t *testing.T) {
	r, _ := http.NewRequest("POST", "https://idp.example.com/saml/sso?user=t&password=t", nil)
	w := httptest.NewRecorder()
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	req := &saml.IdpAuthnRequest{
		IDP:         &s.IDP,
		HTTPRequest: r,
		RelayState:  "relayState",
	}

	_, _, err = CheckUserCredentials(r, w, req)
	if err == nil {
		t.Fatal("Nil error, expected: 'You have entered invalid user'")
	}
}

func TestGenerateSignedSAMLToken(t *testing.T) {
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	user := map[string]interface{}{
		"id":    "test-id",
		"email": "test@host.com",
		"roles": []interface{}{"user"},
	}

	_, err = GenerateSignedSAMLToken(&s.IDP, user)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostData(t *testing.T) {
	s, err := createSAMLIdP()
	if err != nil {
		t.Fatal(err)
	}

	config := []byte(`{
 	    "services": {
 	    	"microservice-user": "http://test.com/users"
 	    }
 	  }`)

	err = ioutil.WriteFile("config.json", config, 0644)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove("config.json")

	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privateBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytes,
	})
	ioutil.WriteFile("system", privateBytes, 0644)

	defer os.Remove("system")

	payload := []byte(`{
 	    "data": "something"
 	  }`)
	client := &http.Client{}

	gock.New("http://test.com").
		Post("/users").
		Reply(201)

	resp, err := postData(client, payload, "http://test.com/users", &s.IDP, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Nil response")
	}
}
