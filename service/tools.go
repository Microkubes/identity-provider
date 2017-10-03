package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/JormungandrK/identity-provider/config"
	"github.com/afex/hystrix-go/hystrix"
)

// FindUser retrives the user by username and password
func FindUser(username, password string) (map[string]interface{}, error) {
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
		resp, err := postData(client, payload, fmt.Sprintf("%s/find", config.Services["microservice-user"]))
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
func postData(client *http.Client, payload []byte, url string) (*http.Response, error) {
	resp, err := client.Post(fmt.Sprintf("%s", url), "application/json", bytes.NewBuffer(payload))
	return resp, err
}
