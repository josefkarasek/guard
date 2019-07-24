package firebase

import (
	"context"

	firebase "firebase.google.com/go"
	fbauth "firebase.google.com/go/auth"
	auth "github.com/appscode/guard/auth"
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
	c FirebaseAuth
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
		c: &FirebaseAuthClient{ac},
	}

	return au, nil
}

func (g Authenticator) UID() string {
	return OrgType
}

func (g *Authenticator) Check(token string) (*authv1.UserInfo, error) {
	t, err := g.c.VerifyIDTokenAndCheckRevoked(context.Background(), token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to authenticate user")
	}
	firebaseUser, err := g.c.GetUser(context.Background(), t.UID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get authenticated user info")
	}
	user := &authv1.UserInfo{
		Username: firebaseUser.UserInfo.Email,
		UID:      t.UID,
	}

	return user, nil
}

// FirebaseAuth defines methods used by the FirebaseAuthClient
type FirebaseAuth interface {
	VerifyIDTokenAndCheckRevoked(context context.Context, idToken string) (*fbauth.Token, error)
	GetUser(context context.Context, uid string) (*fbauth.UserRecord, error)
}

// FirebaseAuthClient wraps the firebase.Client
type FirebaseAuthClient struct {
	*fbauth.Client
}
