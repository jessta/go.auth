package auth

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

const BROWSERID_SCRIPT = "https://browserid.org/include.js"
const VERIFICATION_SERVER = "https://browserid.org/verify"

type BrowserIdProvider struct {
	Host string
}

type BrowserIdUser struct {
	Email string
}

func (self *BrowserIdUser) Userid() string    { return self.Email }
func (self *BrowserIdUser) Username() string  { return self.Email }
func (self *BrowserIdUser) Password() string  { return "" }
func (self *BrowserIdUser) Fullname() string  { return "" }
func (self *BrowserIdUser) EmailAddr() string { return self.Email }
func (self *BrowserIdUser) Icon() string      { return "" }
func (self *BrowserIdUser) Url() string       { return "" }
func (self *BrowserIdUser) Provider() string  { return "browserid" }

func BrowserId(host string) *AuthHandler {
	return New(NewBrowserIdProvider(host))
}

func NewBrowserIdProvider(host string) *BrowserIdProvider {
	return &BrowserIdProvider{Host: host}
}

func (self *BrowserIdProvider) RedirectRequired(r *http.Request) bool {
	_, err := GetUserCookie(r)
	return err != nil
}

func (self *BrowserIdProvider) GetAuthenticatedUser(r *http.Request) (User, error) {
	username, err := GetUserCookie(r)
	if err != nil {
		return nil, err
	}
	return &BrowserIdUser{Email: username}, nil
}

func (self *BrowserIdProvider) Redirect(w http.ResponseWriter, r *http.Request) {
	assertion := r.FormValue("assertion")
	log.Println(assertion)
	if assertion != "" {
		email, err := verify(assertion, self.Host)
		if err == nil {
			SetUserCookie(w, r, email)
			return
		} else {
			w.Write([]byte(err.Error()))
		}
	}
}

func verify(assertion string, host string) (email string, e error) {

	//Verify response with browserid server.
	query := url.Values{"assertion": {assertion}, "audience": {host}}
	response, err := http.PostForm(VERIFICATION_SERVER, query)
	if err != nil {
		return "", err
	}
	r, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return "", err
	}

	var result interface{}
	err = json.Unmarshal(r, &result)
	if err != nil {
		return "", err
	}

	resultmap, ok := result.(map[string]interface{})
	if !ok {
		return "", errors.New("unexpected response")
	}

	status, ok := resultmap["status"].(string)
	if !ok || status != "okay" {
		return "", errors.New("recieved unexpected status: " + status)
	}

	email, ok = resultmap["email"].(string)
	if !ok {
		return "", errors.New("no email address in response")
	}

	audience, ok := resultmap["audience"].(string)
	if !ok || audience != host {
		return "", errors.New("no audience or incorrect audience")
	}

	return email, nil
}
