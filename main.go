package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	types "github.com/bnema/go-echo-pocketbase-boilerplate/types"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	echo "github.com/labstack/echo/v4"

	_ "github.com/joho/godotenv/autoload" // Package for loading .env files
)

type App struct {
	SessionStore     sessions.Store
	PBUrl            string
	PBTradeURL       string
	PBAuthMethodsURL string
	PBAuthRefreshURL string
	OAuthRedirectURL string
}

// NewApp creates a new App struct with all the required fields
func NewApp() *App {
	baseUrl, err := url.Parse(os.Getenv("PB_URL"))
	if err != nil {
		panic(err)
	}

	app := &App{
		SessionStore: sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET"))),
		PBUrl:        baseUrl.String(),
	}

	authMethodsUrl, err := baseUrl.Parse("/api/collections/users/auth-methods")
	if err != nil {
		panic(err)
	}
	app.PBAuthMethodsURL = authMethodsUrl.String()

	authRefreshUrl, err := baseUrl.Parse("/api/collections/users/auth-refresh")
	if err != nil {
		panic(err)
	}
	app.PBAuthRefreshURL = authRefreshUrl.String()

	tradeUrl, err := baseUrl.Parse("/api/collections/users/auth-with-oauth2")
	if err != nil {
		panic(err)
	}
	app.PBTradeURL = tradeUrl.String()

	oauthRedirectURL, ok := os.LookupEnv("OAUTH_REDIRECT_URL")
	if !ok {
		panic("OAUTH_REDIRECT_URL environment variable is not set")
	}
	app.OAuthRedirectURL = oauthRedirectURL

	return app
}

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

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bodyBytes, v)
	if err != nil {
		return err
	}

	return nil
}

// PostJSON sends a POST request to a given URL with a JSON body, and decodes the response JSON into 'v' interface
func PostJSON(url string, body interface{}, v interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to post JSON: %w", err)
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(v)
}

// getAuthMethods retrieves available authentication methods for a given provider
func (app *App) getAuthMethods(provider string) (types.AuthMethodsResponse, error) {
	authMethods := types.AuthMethodsResponse{}
	err := GetJSON(app.PBAuthMethodsURL, &authMethods)
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

// refreshAuthToken refreshes an existing token
func (app *App) refreshAuthToken(token string) (types.RefreshResponse, error) {
	refreshResponse := types.RefreshResponse{}
	err := PostJSON(app.PBAuthRefreshURL, token, &refreshResponse)
	if err != nil {
		return types.RefreshResponse{}, err
	}

	return refreshResponse, nil
}

// tradeCodeForToken exchanges an authorization code for a token
func (app *App) tradeCodeForToken(oAuthRequest types.OAuthRequest) (types.TradeResponse, error) {
	tradeResponse := types.TradeResponse{}
	err := PostJSON(app.PBTradeURL, oAuthRequest, &tradeResponse)
	if err != nil {
		return types.TradeResponse{}, err
	}

	return tradeResponse, nil
}

// loginRoute handles the '/login' endpoint and initiates OAuth authentication
func (app *App) loginRoute(c echo.Context) error {
	provider := c.QueryParam("provider")
	authMethods, err := app.getAuthMethods(provider)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("Failed to get auth methods: %v", err),
		})
	}

	session, err := app.SessionStore.Get(c.Request(), "session") // Get session for this request
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to get session: %v", err),
		})
	}
	session.Options.MaxAge = 60 * 15 // Set session max age to 15 minutes
	session.Options.HttpOnly = true  // Set session cookie to HTTP only
	session.Values["provider"] = provider
	session.Values["state"] = authMethods.AuthProviders[0].State
	session.Values["codeVerifier"] = authMethods.AuthProviders[0].CodeVerifier
	session.Values["authUrl"] = authMethods.AuthProviders[0].AuthURL
	session.Save(c.Request(), c.Response()) // Save session data

	return c.Redirect(302, authMethods.AuthProviders[0].AuthURL) // Redirect user to OAuth URL
}

// redirectRoute handles the '/oauth-redirect' endpoint and finalizes the OAuth authentication process
func (app *App) redirectRoute(c echo.Context) error {
	session, _ := app.SessionStore.Get(c.Request(), "session") // Get session for this request
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
		RedirectURL:  app.OAuthRedirectURL,
		State:        state,
	}

	tradeResponse, err := app.tradeCodeForToken(oAuthRequest)
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

// isLoggedIn is a middleware that checks if a user is logged in
func (app *App) isLoggedIn(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		session, err := app.SessionStore.Get(c.Request(), "session")
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

// verifyToken is a middleware that verifies the validity of a token
func (app *App) verifyToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		session := c.Get("session").(*sessions.Session)
		token := session.Values["token"].(string)
		refreshResponse, err := app.refreshAuthToken(token)
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

// TestPrivateRoute is a test endpoint that requires authentication
func TestPrivateRoute(c echo.Context) error {
	// return a json response "you are logged in"
	return c.JSON(200, map[string]string{
		"message": "you are logged in",
	})

}

// Initializes the server and defines endpoints
func main() {
	app := NewApp()

	e := echo.New()
	e.Use(session.Middleware(app.SessionStore)) // Use session middleware

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "/") // Define '/' endpoint
	})

	e.GET("/login", app.loginRoute) // Define '/login' endpoint

	e.GET("/oauth-redirect", app.redirectRoute) // Define '/oauth-redirect' endpoint

	e.GET("/private", TestPrivateRoute, app.isLoggedIn, app.verifyToken) // Define '/private' endpoint

	e.GET("/debug", func(c echo.Context) error {
		provider := c.QueryParam("provider")
		return c.String(http.StatusOK, provider)
	})

	e.Logger.Fatal(e.Start(":8080")) // Start server on port 8080
}
