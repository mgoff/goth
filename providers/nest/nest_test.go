package nest_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/nest"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := nestProvider()
	a.Equal(provider.ClientKey, os.Getenv("NEST_KEY"))
	a.Equal(provider.Secret, os.Getenv("NEST_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), nestProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := nestProvider()
	session, err := provider.BeginAuth("STATE")
	s := session.(*nest.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://home.nest.com/login/oauth2")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("NEST_KEY")))
	a.Contains(s.AuthURL, "state=STATE")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := nestProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://home.nest.com/login/oauth2","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*nest.Session)
	a.Equal(session.AuthURL, "https://home.nest.com/login/oauth2")
	a.Equal(session.AccessToken, "1234567890")
}

func nestProvider() *nest.Provider {
	return nest.New(os.Getenv("NEST_KEY"), os.Getenv("NEST_SECRET"), "/foo", "app")
}
