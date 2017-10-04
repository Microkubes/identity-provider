package service

import (
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"gopkg.in/h2non/gock.v1"
)

func TestFindUser(t *testing.T) {
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

	user, err := FindUser("jon", "qwerty123")
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("Nil user")
	}
}

func TestFindUserBadConfig(t *testing.T) {
	config := []byte(`{
	    "services": {
	    	"microservice-user": "http://127.0.0.1:8081/not-exists"
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

	_, err = FindUser("jon", "qwerty123")
	if err == nil {
		t.Fatal("Nil error, expected: Post http://127.0.0.1:8081/not-exists/find: gock: cannot match any request")
	}
}

func TestFindUserBadStatusCode(t *testing.T) {
	config := []byte(`{
	    "services": {
	    	"microservice-user": "http://127.0.0.1:8082/users/bad-status-code"
	    }
	  }`)

	err := ioutil.WriteFile("config.json", config, 0644)
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

	_, err = FindUser("jon", "qwerty123")

	if err == nil {
		t.Fatal("Nil error, expected: Internal Server Error")
	}
}

func TestPostData(t *testing.T) {
	payload := []byte(`{
	    "data": "something"
	  }`)
	client := &http.Client{}

	gock.New("http://test.com").
		Post("/users").
		Reply(201)

	resp, err := postData(client, payload, "http://test.com/users")
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Nil response")
	}
}
