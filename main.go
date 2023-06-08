package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	types "github.com/bnema/go-dysproof-api/types" // Importing custom types for this project
	"github.com/gorilla/sessions"                  // Library for managing sessions
	"github.com/labstack/echo-contrib/session"     // Echo middleware for session management
	echo "github.com/labstack/echo/v4"             // HTTP server framework

	_ "github.com/joho/godotenv/autoload" // Package for loading .env files
)

var (
	// Configure your app using environment variables
	sessionStore        = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	pb                  = os.Getenv("PB_URL")
	pbTradeURL          = pb + "/api/collections/users/auth-with-oauth2"
	pbAuthMethodsURL    = pb + "/api/collections/users/auth-methods"
	pbAuthRefreshURL    = pb + "/api/collections/users/auth-refresh"
	OauthRedirectURL, _ = os.LookupEnv("OAUTH_REDIRECT_URL")
)

// GetJSON sends a GET request to a given URL and decodes the response JSON into 'v' interface
func GetJSON(url string, v interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("received non 200 response code")
	}

	return json.NewDecoder(resp.Body).Decode(v)
}

// PostJSON sends a POST request to a given URL with a JSON body, and decodes the response JSON into 'v' interface
func PostJSON(url string, body interface{}, v interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(v)
}

// getAuthMethods retrieves available authentication methods for a given provider
func getAuthMethods(provider string) (types.AuthMethodsResponse, error) {
	authMethods := types.AuthMethodsResponse{}
	err := GetJSON(pbAuthMethodsURL, &authMethods)
	if err != nil {
		return types.AuthMethodsResponse{}, err
	}

	filteredAuthMethods := types.AuthMethodsResponse{}
	for _, authMethod := range authMethods.AuthProviders {
		if authMethod.Name == provider {
			filteredAuthMethods.AuthProviders = append(filteredAuthMethods.AuthProviders, authMethod)
		}
	}

	return filteredAuthMethods, nil

}

func refreshAuthToken(token string) (types.RefreshResponse, error) {
	refreshResponse := types.RefreshResponse{}
	err := PostJSON(pbAuthRefreshURL, token, &refreshResponse)
	if err != nil {
		return types.RefreshResponse{}, err
	}

	return refreshResponse, nil
}

// tradeCodeForToken exchanges an authorization code for a token
func tradeCodeForToken(oAuthRequest types.OAuthRequest) (types.TradeResponse, error) {
	tradeResponse := types.TradeResponse{}
	err := PostJSON(pbTradeURL, oAuthRequest, &tradeResponse)
	if err != nil {
		return types.TradeResponse{}, err
	}

	return tradeResponse, nil
}

// loginRoute handles the '/login' endpoint and initiates OAuth authentication
func loginRoute(c echo.Context) error {
	provider := c.QueryParam("provider")
	authMethods, err := getAuthMethods(provider)
	if err != nil {
		return c.JSON(400, map[string]string{
			"error": "Failed to get auth methods",
		})
	}

	session, _ := sessionStore.Get(c.Request(), "session") // Get session for this request
	session.Options.MaxAge = 60 * 15                       // Set session max age to 15 minutes
	session.Options.HttpOnly = true                        // Set session cookie to HTTP only
	session.Values["provider"] = provider
	session.Values["state"] = authMethods.AuthProviders[0].State
	session.Values["codeVerifier"] = authMethods.AuthProviders[0].CodeVerifier
	session.Values["authUrl"] = authMethods.AuthProviders[0].AuthURL
	session.Save(c.Request(), c.Response()) // Save session data

	return c.Redirect(302, authMethods.AuthProviders[0].AuthURL) // Redirect user to OAuth URL
}

// redirectRoute handles the '/oauth-redirect' endpoint and finalizes the OAuth authentication process
func redirectRoute(c echo.Context) error {
	session, _ := sessionStore.Get(c.Request(), "session") // Get session for this request
	provider := session.Values["provider"].(string)
	state := session.Values["state"].(string)
	codeVerifier := session.Values["codeVerifier"].(string)
	code := c.QueryParam("code")

	if state != c.QueryParam("state") {
		return c.JSON(400, map[string]string{
			"error": "Invalid state",
		})
	}

	oAuthRequest := types.OAuthRequest{
		Provider:     provider,
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURL:  OauthRedirectURL,
		State:        state,
	}

	tradeResponse, err := tradeCodeForToken(oAuthRequest)
	if err != nil {
		return c.JSON(400, map[string]string{
			"error": "Failed to trade code for token",
		})
	}

	// Save token in session
	session.Values["token"] = tradeResponse.Token // Save token in session

	// Save session data
	err = session.Save(c.Request(), c.Response())
	if err != nil {
		return c.JSON(500, map[string]string{
			"error": "Failed to save session",
		})
	}

	// close the page
	return c.HTML(200, "You can close this page now")

}

func isLoggedIn(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		session, err := sessionStore.Get(c.Request(), "session")
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Session retrieval failed",
			})
		}

		if session.Values["token"] == nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Not logged in",
			})
		}
		c.Set("session", session)
		return next(c)
	}
}

// Middleware function to verify token
func verifyToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		session := c.Get("session").(*sessions.Session)
		token := session.Values["token"].(string)
		refreshResponse, err := refreshAuthToken(token)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid token",
			})
		}

		session.Values["token"] = refreshResponse.Token // Save refreshed token in session
		err = session.Save(c.Request(), c.Response())   // Save session data
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to save session",
			})
		}

		return next(c)
	}
}

func TestPrivateRoute(c echo.Context) error {
	// return a json response "you are logged in"
	return c.JSON(200, map[string]string{
		"message": "you are logged in",
	})

}

// Initializes the server and defines endpoints
func main() {
	e := echo.New()
	e.Use(session.Middleware(sessionStore)) // Apply session middleware

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "/") // Define '/' endpoint
	})

	e.GET("/login", loginRoute) // Define '/login' endpoint

	e.GET("/oauth-redirect", redirectRoute) // Define '/oauth-redirect' endpoint

	e.GET("/private", TestPrivateRoute, isLoggedIn, verifyToken) // Define '/private' endpoint

	e.Logger.Fatal(e.Start(":8080")) // Start server on port 8080
}
