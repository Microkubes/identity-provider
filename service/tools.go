package service

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/JormungandrK/identity-provider/config"
	jormungandrSaml "github.com/JormungandrK/microservice-security/saml"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/crewjam/saml"
	jwt "github.com/dgrijalva/jwt-go"
)

// FindUser retrives the user by username and password
func FindUser(username string, password string, idp *saml.IdentityProvider) (map[string]interface{}, error) {
	config, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}

	userPayload := map[string]interface{}{
		"username": username,
		"password": password,
	}
	payload, err := json.Marshal(userPayload)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	output := make(chan *http.Response, 1)
	errorsChan := hystrix.Go("user-microservice.find_by_email", func() error {
		resp, err := postData(client, payload, fmt.Sprintf("%s/find", config.Services["microservice-user"]), idp)
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

	return resp, nil
}

// postData makes post request
func postData(client *http.Client, payload []byte, url string, idp *saml.IdentityProvider) (*http.Response, error) {
	config, err := config.LoadConfig("")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	expire := time.Now().AddDate(0, 0, 1)
	encodedPrivatekKey := x509.MarshalPKCS1PrivateKey(idp.Key.(*rsa.PrivateKey))
	claims := jormungandrSaml.TokenClaims{}
	claims.Audience = fmt.Sprintf("%s/saml/metadata", config.Services["microservice-user"])
	claims.Attributes = map[string][]string{
		"userId":   []string{"system"},
		"username": []string{"system"},
		"roles":    []string{"system"},
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := tokenHS.SignedString(encodedPrivatekKey)
	if err != nil {
		return nil, err
	}
	cookie := http.Cookie{"token", tokenStr, "", "", expire, expire.Format(time.UnixDate), 86400, true, true, "", []string{}}
	req.AddCookie(&cookie)

	req.Host = "user.services.jormugandr.org"

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// checks user credentials
func CheckUserCredentials(r *http.Request, w http.ResponseWriter, req *saml.IdpAuthnRequest) (string, string, error) {
	username := strings.TrimSpace(r.FormValue("user"))
	password := strings.TrimSpace(r.FormValue("password"))

	if username == "" || password == "" {
		return "", "", fmt.Errorf("Credentials required!")
	}

	if err := validateCredentials(username, password); err != nil {
		return "", "", err
	}

	return username, password, nil
}

// ValidateCredentials validates the user credential( username/password )
func validateCredentials(username, pass string) error {
	if match, _ := regexp.MatchString("^([a-zA-Z0-9@]{4,50})$", username); !match {
		return fmt.Errorf("You have entered invalid user")
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
		"username": user["username"].(string),
		"userId":   user["id"].(string),
		"roles":    roles,
		"email":    user["email"].(string),
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := tokenHS.SignedString(encodedPrivatekKey)

	return tokenStr, err
}
