package smartthings_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/smartthings"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := smartthingsProvider()
	a.Equal(provider.ClientKey, os.Getenv("SMARTTHINGS_KEY"))
	a.Equal(provider.Secret, os.Getenv("SMARTTHINGS_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), smartthingsProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := smartthingsProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*smartthings.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "graph.api.smartthings.com/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("SMARTTHINGS_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=app")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := smartthingsProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://graph.api.smartthings.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*smartthings.Session)
	a.Equal(session.AuthURL, "https://graph.api.smartthings.com/oauth/authorize")
	a.Equal(session.AccessToken, "1234567890")
}

func smartthingsProvider() *smartthings.Provider {
	return smartthings.New(os.Getenv("SMARTTHINGS_KEY"), os.Getenv("SMARTTHINGS_SECRET"), "/foo", "app")
}
