package framework

import (
	"path/filepath"

	"github.com/appscode/go/crypto/rand"
	. "github.com/onsi/gomega"
	"github.com/spf13/afero"
	"gomodules.xyz/cert/certstore"
	"k8s.io/client-go/kubernetes"
)

type Framework struct {
	KubeClient kubernetes.Interface
	namespace  string
	CertStore  *certstore.CertStore
}

func New(kubeClient kubernetes.Interface) *Framework {
	store, err := certstore.NewCertStore(afero.NewMemMapFs(), filepath.Join("", "pki"))
	Expect(err).NotTo(HaveOccurred())

	err = store.InitCA()
	Expect(err).NotTo(HaveOccurred())

	return &Framework{
		KubeClient: kubeClient,
		namespace:  rand.WithUniqSuffix("test-guard"),
		CertStore:  store,
	}
}

func (f *Framework) Invoke() *Invocation {
	return &Invocation{
		Framework: f,
		app:       "guard",
	}
}

type Invocation struct {
	*Framework
	app string
}
