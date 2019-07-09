package firebase

import (
	"context"

	firebase "firebase.google.com/go"
	fauth "firebase.google.com/go/auth"
	"github.com/appscode/guard/auth"
	"github.com/pkg/errors"
	authv1 "k8s.io/api/authentication/v1"
)

const (
	OrgType = "firebase"
)

func init() {
	auth.SupportedOrgs = append(auth.SupportedOrgs, OrgType)
}

type Authenticator struct {
	Client *fauth.Client
}

func New(opts Options) (auth.Interface, error) {
	a, err := firebase.NewApp(context.Background(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create firebase app")
	}

	ac, err := a.Auth(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create firebase client")
	}

	au := &Authenticator{
		Client: ac,
	}

	return au, nil
}

func (g Authenticator) UID() string {
	return OrgType
}

func (g *Authenticator) Check(token string) (*authv1.UserInfo, error) {
	t, err := g.Client.VerifyIDTokenAndCheckRevoked(context.Background(), token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to authenticate user")
	}
	firebaseUser, err := g.Client.GetUser(context.Background(), t.UID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get authenticated user info")
	}
	user := &authv1.UserInfo{
		Username: firebaseUser.UserInfo.Email,
		UID:      t.UID,
	}

	return user, nil
}
