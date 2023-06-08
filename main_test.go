package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	types "github.com/bnema/go-dysproof-api/types"
	echo "github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestGetJSON(t *testing.T) {
	// Initialize echo context
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	_ = e.NewContext(req, rec)

	// what to do with c?

	// Mock data
	v := &types.AuthMethodsResponse{}

	// Note: Here we assume the URL you are requesting from returns the correct JSON format needed.
	// In a real testing scenario, you would want to set up a local test server that returns a predefined JSON
	err := GetJSON("http://example.com", v)
	assert.NoError(t, err)
}

func TestPostJSON(t *testing.T) {
	// Initialize echo context
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	_ = e.NewContext(req, rec)

	// Mock data
	body := map[string]string{"foo": "bar"}
	v := &types.RefreshResponse{}

	// Note: Here we assume the URL you are posting to returns the correct JSON format needed.
	// In a real testing scenario, you would want to set up a local test server that returns a predefined JSON
	err := PostJSON("http://example.com", body, v)
	assert.NoError(t, err)
}

func TestLoginRoute(t *testing.T) {
	// Initialize echo context
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set the query parameter
	q := req.URL.Query()
	q.Add("provider", "github")
	req.URL.RawQuery = q.Encode()

	// Call the function
	if assert.NoError(t, loginRoute(c)) {
		assert.Equal(t, http.StatusFound, rec.Code) // Redirect should return 302
	}
}

func TestRedirectRoute(t *testing.T) {
	// Initialize echo context
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/oauth-redirect", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set the query parameter
	q := req.URL.Query()
	q.Add("provider", "github")
	req.URL.RawQuery = q.Encode()

	// Call the function
	if assert.NoError(t, redirectRoute(c)) {
		assert.Equal(t, http.StatusOK, rec.Code) // Expecting HTML return with code 200
	}
}

func TestTestPrivateRoute(t *testing.T) {
	// Initialize echo context
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Call the function
	if assert.NoError(t, TestPrivateRoute(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, `{"message":"you are logged in"}`, rec.Body.String())
	}
}
