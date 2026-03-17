package auth

import (
	"fmt"
	"net"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosClient defines the interface expected by the HBase client.
type KerberosClient interface {
	PerformSASLHandshake(conn net.Conn, spn string) error
	RenewTicket() error
	Close()
}

type krbAuth struct {
	kClient *client.Client
}

// NewKerberosClient initializes the gokrb5 client using a krb5.conf file and a keytab.
func NewKerberosClient(krb5ConfPath, keytabPath, principal, realm string) (KerberosClient, error) {
	cfg, err := config.Load(krb5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("could not load krb5.conf: %w", err)
	}

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("could not load keytab: %w", err)
	}

	kClient := client.NewWithKeytab(principal, realm, kt, cfg)

	err = kClient.Login()
	if err != nil {
		return nil, fmt.Errorf("kerberos login failed for %s@%s: %w", principal, realm, err)
	}

	return &krbAuth{
		kClient: kClient,
	}, nil
}

func (k *krbAuth) PerformSASLHandshake(conn net.Conn, spn string) error {
	spnegoClient := spnego.SPNEGOClient(k.kClient, spn)

	token, err := spnegoClient.InitSecContext()
	if err != nil {
		return fmt.Errorf("failed to generate initial security token for %s: %w", spn, err)
	}
	_ = token

	return nil
}

func (k *krbAuth) RenewTicket() error {
	err := k.kClient.Login()
	if err != nil {
		return fmt.Errorf("failed to renew kerberos ticket: %w", err)
	}
	return nil
}

func (k *krbAuth) Close() {
	if k.kClient != nil {
		k.kClient.Destroy()
	}
}
