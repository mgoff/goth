package nest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with Facebook.
type Session struct {
	AuthURL     string
	AccessToken string
	ExpiresAt   time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Nest provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Yammer and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {

	// Setup Params to get the access token
	v := url.Values{
		"grant_type": {"authorization_code"},
		"code":       CondVal(params.Get("code")),
	}

	// Call our own method to make the request from Nest
	p := provider.(*Provider)
	authData, err := retrieveAuthData(p, tokenURL, v)
	if err != nil {
		return "", err
	}

	// Get values from the json response
	token := authData["access_token"].(string)
	expiresIn := authData["expires_in"].(float64)

	// Save values in our session objects
	s.AccessToken = token
	s.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Debug
	fmt.Println("Access Token from Nest:", s.AccessToken)
	fmt.Println("Expires At from Nest:", s.ExpiresAt)

	return token, err
}

//  Get access token and expiration date
func retrieveAuthData(p *Provider, TokenURL string, v url.Values) (map[string]interface{}, error) {

	// Add client id and secret
	v.Set("client_id", p.ClientKey)
	v.Set("client_secret", p.Secret)

	// Make the post request
	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Debug
	dump, err := httputil.DumpRequest(req, true)
	fmt.Printf("%q", dump)

	r, err := p.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	var objmap map[string]interface{}

	err = json.Unmarshal(body, &objmap)

	if err != nil {
		return nil, err
	}
	return objmap, nil
}

//CondVal convert string in string array
func CondVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
