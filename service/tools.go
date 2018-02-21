package service

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/JormungandrK/identity-provider/config"
	// jormungandrSaml "github.com/JormungandrK/microservice-security/saml"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/crewjam/saml"
	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

// FindUser retrives the user by email and password
func FindUser(email string, password string, idp *saml.IdentityProvider, cfg *config.Config) (map[string]interface{}, error) {
	userPayload := map[string]interface{}{
		"email":    email,
		"password": password,
	}
	payload, err := json.Marshal(userPayload)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	output := make(chan *http.Response, 1)
	errorsChan := hystrix.Go("user-microservice.find_by_email", func() error {
		resp, err := postData(client, payload, fmt.Sprintf("%s/find", cfg.Services["microservice-user"]), idp, cfg)
		if err != nil {
			return err
		}
		output <- resp
		return nil
	}, nil)

	var createUserResp *http.Response
	select {
	case out := <-output:
		createUserResp = out
	case respErr := <-errorsChan:
		return nil, respErr
	}

	// Inspect status code from response
	body, _ := ioutil.ReadAll(createUserResp.Body)
	if createUserResp.StatusCode != 200 {
		err := errors.New(string(body))
		return nil, err
	}

	var resp map[string]interface{}
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	if active, ok := resp["active"]; ok {
		if active != nil {
			if _, ok := active.(bool); ok && !active.(bool) {
				return nil, fmt.Errorf("account-not-activated")
			}
		}
	}

	return resp, nil
}

// postData makes post request
func postData(client *http.Client, payload []byte, url string, idp *saml.IdentityProvider, cfg *config.Config) (*http.Response, error) {
	key, err := ioutil.ReadFile(cfg.SystemKey)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	randUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{
		"iss":      "identity-provider",
		"exp":      time.Now().Add(time.Duration(30) * time.Second).Unix(),
		"jti":      randUUID.String(),
		"nbf":      0,
		"sub":      "identity-provider",
		"scope":    "api:read",
		"userId":   "system",
		"username": "system",
		"roles":    "system",
	}

	tokenRS := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token, err := tokenRS.SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// checks user credentials
func CheckUserCredentials(r *http.Request, w http.ResponseWriter, req *saml.IdpAuthnRequest) (string, string, error) {
	email := strings.TrimSpace(r.FormValue("email"))
	password := strings.TrimSpace(r.FormValue("password"))

	if email == "" || password == "" {
		return "", "", fmt.Errorf("Credentials required!")
	}

	if err := validateCredentials(email, password); err != nil {
		return "", "", err
	}

	return email, password, nil
}

// ValidateCredentials validates the user credential( email/password )
func validateCredentials(email, pass string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("You have entered invalid email")
	}
	if len(pass) < 6 {
		return fmt.Errorf("You have entered invalid password")
	}
	return nil
}

// generateSignedSAMLToken generates signed SAML token
func GenerateSignedSAMLToken(idp *saml.IdentityProvider, user map[string]interface{}) (string, error) {
	roles := []string{}
	for _, v := range user["roles"].([]interface{}) {
		roles = append(roles, v.(string))
	}

	encodedPrivatekKey := x509.MarshalPKCS1PrivateKey(idp.Key.(*rsa.PrivateKey))
	claims := jwt.MapClaims{
		"userId": user["id"].(string),
		"email":  user["email"].(string),
		"roles":  roles,
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := tokenHS.SignedString(encodedPrivatekKey)

	return tokenStr, err
}
