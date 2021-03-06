package auth

import (
	"net/http"
	"net/url"
	"time"
)

// AuthHandler is an HTTP Handler that authenticates an http.Request using
// the specified AuthProvider.
type AuthHandler struct {
	// provider specifies the policy for authenticating a user.
	provider AuthProvider

	// Success specifies a function to execute upon successful authentication.
	// If Success is nil, the DefaultSuccess func is used.
	Success func(w http.ResponseWriter, r *http.Request, user User)

	// Failure specifies a function to execute upon failing authentication.
	// If Failure is nil, the DefaultFailure func is used.
	Failure func(w http.ResponseWriter, r *http.Request, err error)
}

// New allocates and returns a new AuthHandler, using the specified
// AuthProvider.
func New(p AuthProvider) *AuthHandler {
	return &AuthHandler{ provider : p }
}

// Google allocates and returns a new AuthHandler, using the GoogleProvider.
func Google(client, secret, redirect string) *AuthHandler {
	return New(NewGoogleProvider(client, secret, redirect))
}

// Github allocates and returns a new AuthHandler, using the GithubProvider.
func Github(client, secret string) *AuthHandler {
	return New(NewGithubProvider(client, secret))
}

// OpenId allocates and returns a new AuthHandler, using the OpenIdProvider.
func OpenId(url string) *AuthHandler {
	return New(NewOpenIdProvider(url))
}

// Twitter allocates and returns a new AuthHandler, using the TwitterProvider.
func Twitter(key, secret, callback string) *AuthHandler {
	return New(NewGoogleProvider(key, secret, callback))
}

// ServeHTTP handles the authentication request and manages the
// authentication flow.
func (self *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Redirect the user, if required
	if self.provider.RedirectRequired(r) == true {
		self.provider.Redirect(w, r)
		return
	}

	// Get the authenticated user Id
	user, err := self.provider.GetAuthenticatedUser(r)
	if err != nil {
		// If there was a problem, invoke failure
		if self.Failure == nil {
			DefaultFailure(w, r, err)
		} else {
			self.Failure(w, r, err)
		}
		return
	}

	// Invoke the success function
	if self.Success == nil {
		DefaultSuccess(w, r, user)
	} else {
		self.Success(w, r, user)
	}
}

// DefaultSuccess will redirect a User, using an http.Redirect, to the
// Config.LoginSuccessRedirect url upon successful authentication.
var DefaultSuccess = func(w http.ResponseWriter, r *http.Request, u User) {
	SetUserCookie(w, r, u.Username())
	http.Redirect(w, r, Config.LoginSuccessRedirect, http.StatusSeeOther)
}

// DefaultFailure will return an http Forbidden code indicating a failed
// authentication.
var DefaultFailure = func(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusForbidden)
}

// An AuthProvider interface is used by an AuthHandler to authenticate a user
// over HTTP. Example implementations of an AuthProvider might be OAuth, OpenId,
// or SAML.
type AuthProvider interface {

	// RedirectRequired returns a boolean value indicating if the request
	// should be redirected to the authentication provider's login screen.
	RedirectRequired(r *http.Request) bool

	// Redirect will do an http.Redirect, sending the user to the authentication
	// provider's login screen.
	Redirect(w http.ResponseWriter, r *http.Request)

	// GetAuthenticatedUser will retrieve the authenticated User from the
	// http.Request object.
	GetAuthenticatedUser(r *http.Request) (User, error)
}

// AuthConfig holds configuration parameters used when authenticating a user and
// creating a secure cookie user session.
type AuthConfig struct {
	CookieSecret          []byte
	CookieName            string
	CookieExp             time.Duration
	CookieMaxAge          int
	LoginRedirect         string
	LoginSuccessRedirect  string
}

// Config is the default implementation of Config, and is used by
// DetaultAuthCallback, Secure, and SecureFunc.
var Config = &AuthConfig{
	CookieName:            "UID",
	CookieExp:             time.Hour * 24 * 14,
	CookieMaxAge:          0,
	LoginRedirect:         "/auth/login",
	LoginSuccessRedirect:  "/",
}

// A User is returned by the AuthProvider upon success authentication.
type User interface {
	Userid() string
	Username() string
	Password() string
	Fullname() string
	EmailAddr() string
	Icon() string
	Url() string
	Provider() string
}

// SecureFunc will attempt to verify a user session exists prior to executing
// the http.HandlerFunc. If no valid sessions exists, the user will be
// redirected to the Config.LoginRedirect Url.
func SecureFunc(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := GetUserCookie(r)

		//if no active user session then authorize user
		if user == "" || err != nil {
			http.Redirect(w, r, Config.LoginRedirect, http.StatusSeeOther)
			return
		}

		//else, add the user to the URL and continue
		r.URL.User = url.User(user)
		handler(w, r)
	}
}

// Secure will attempt to verify a user session exists prior to executing
// the http.Handler ServeHTTP function. If no valid sessions exists, the user
// will be redirected to the Config.LoginRedirect Url.
func Secure(handler http.Handler) http.Handler {
	return &secureHandler{ handler }
}

// secureHandler wraps an http.Handler and ServeHTTP function in order
// to authenticate the incoming request.
type secureHandler struct {
	handler http.Handler
}

func (self *secureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserCookie(r)

	//if no active user session then authorize user
	if user == "" || err != nil {
		http.Redirect(w, r, Config.LoginRedirect, http.StatusSeeOther)
		return
	}

	//else, add the user to the URL and continue
	r.URL.User = url.User(user)
	self.handler.ServeHTTP(w, r)
}

