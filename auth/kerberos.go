package auth

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosClient defines the interface expected by the HBase client.
type KerberosClient interface {
	PerformSASLHandshake(ctx context.Context, conn net.Conn, spn string) error
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

func writeSASLToken(conn net.Conn, token []byte) error {
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(token)))

	if _, err := conn.Write(lengthBuf); err != nil {
		return fmt.Errorf("failed to write token length: %w", err)
	}
	if _, err := conn.Write(token); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
	}
	return nil
}

func readSASLToken(conn net.Conn) ([]byte, error) {
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read token length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	token := make([]byte, length)
	if _, err := io.ReadFull(conn, token); err != nil {
		return nil, fmt.Errorf("failed to read token: %w", err)
	}

	return token, nil
}

func (k *krbAuth) PerformSASLHandshake(ctx context.Context, conn net.Conn, spn string) error {
	// Respect context deadlines so the handshake doesn't block forever if the server hangs
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{}) // Reset after handshake
	}

	spnegoClient := spnego.SPNEGOClient(k.kClient, spn)

	st, err := spnegoClient.InitSecContext()
	if err != nil {
		return fmt.Errorf("failed to generate initial security token for %s: %w", spn, err)
	}

	b, err := st.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal SPNEGO token: %w", err)
	}

	if err := writeSASLToken(conn, b); err != nil {
		return fmt.Errorf("failed to send SASL token: %w", err)
	}

	serverResponse, err := readSASLToken(conn)
	if err != nil {
		return fmt.Errorf("failed to read SASL challenge from server: %w", err)
	}

	var respToken spnego.SPNEGOToken
	if err := respToken.Unmarshal(serverResponse); err != nil {
		return fmt.Errorf("failed to unmarshal server SPNEGO response: %w", err)
	}

	if !respToken.Resp {
		return fmt.Errorf("expected NegTokenResp from server, got something else")
	}

	state := respToken.NegTokenResp.State()

	switch state {
	case spnego.NegStateAcceptCompleted:
		return nil

	case spnego.NegStateReject:
		return fmt.Errorf("kerberos negotiation rejected by server")

	case spnego.NegStateAcceptIncomplete:
		return fmt.Errorf("server requested multi-step SPNEGO which is unhandled")

	default:
		return fmt.Errorf("unknown SPNEGO negotiation state from server: %v", state)
	}
}

// RenewTicket explicitly requests a new TGT.
func (k *krbAuth) RenewTicket() error {
	err := k.kClient.Login()
	if err != nil {
		return fmt.Errorf("failed to renew kerberos ticket: %w", err)
	}
	return nil
}

// Close gracefully destroys the Kerberos client session.
func (k *krbAuth) Close() {
	if k.kClient != nil {
		k.kClient.Destroy()
	}
}
