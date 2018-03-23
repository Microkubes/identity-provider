package samlidp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Microkubes/identity-provider/db"
)

func TestLoadTemplateFile(t *testing.T) {
	_, err := loadTemplateFile("../public/login/login-form.html")
	if err != nil {
		t.Fatal(err)
	}

	_, err = loadTemplateFile("public/login/not-exists.html")
	if err == nil {
		t.Fatal("Nil error, expected: open public/login/not-exists.html: no such file or directory")
	}
}

func TestRenderTemplate(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso", nil)
	data := map[string]interface{}{
		"Error":       "",
		"URL":         "https://idp.example.com/saml/sso",
		"SAMLRequest": "dhjsajdh2o3f78n24r89jndfsf78hfd78f",
		"RelayState":  "sdi894878r2378h223h0228e7823e37232",
	}
	renderTemplate("../public/login/login-form.html", 200, data, w, r)
}

func TestBadRequestForm(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso", nil)

	BadRequestForm(w, r, "Bad request", "../public/bad-request.html")
}

func TestErrorForm(t *testing.T) {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso", nil)

	ErrorForm(w, r, "Internal Server Error", 500, "../public/error.html")
}

func TestLoginForm(t *testing.T) {
	w := httptest.NewRecorder()
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

	LoginForm(w, r, req, "https://idp.example.com/saml/idp/login", "", "../public/login/login-form.html")
}
