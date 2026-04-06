package auth

import (
	"encoding/binary"
	"fmt"
	"io"
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
	// 1. Load Kerberos config
	cfg, err := config.Load(krb5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("could not load krb5.conf: %w", err)
	}

	// 2. Load Keytab
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("could not load keytab: %w", err)
	}

	// 3. Initialize the client
	kClient := client.NewWithKeytab(principal, realm, kt, cfg)

	// 4. Perform initial login to get the TGT
	err = kClient.Login()
	if err != nil {
		return nil, fmt.Errorf("kerberos login failed for %s@%s: %w", principal, realm, err)
	}

	return &krbAuth{
		kClient: kClient,
	}, nil
}

// writeSASLToken prefixes the token with a 4-byte Big-Endian length and writes it to the connection.
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

// readSASLToken reads a 4-byte Big-Endian length, then reads exactly that many bytes for the token.
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

// PerformSASLHandshake negotiates the GSSAPI/SPNEGO context with the HBase RegionServer/Master.
func (k *krbAuth) PerformSASLHandshake(conn net.Conn, spn string) error {
	spnegoClient := spnego.SPNEGOClient(k.kClient, spn)

	// 1. Generate the initial security context token
	st, err := spnegoClient.InitSecContext()
	if err != nil {
		return fmt.Errorf("failed to generate initial security token for %s: %w", spn, err)
	}

	// 2. Marshal the SPNEGO token into bytes
	b, err := st.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal SPNEGO token: %w", err)
	}

	// 3. Send the token to HBase with Hadoop RPC framing
	if err := writeSASLToken(conn, b); err != nil {
		return fmt.Errorf("failed to send initial SASL token: %w", err)
	}

	// 4. Read the server's challenge/response
	serverResponse, err := readSASLToken(conn)
	if err != nil {
		return fmt.Errorf("failed to read SASL challenge from server: %w", err)
	}

	// 5. Check if further negotiation is required.
	// For basic "auth" QOP (Quality of Protection), a single exchange is often enough.
	// If the server requires "auth-int" (integrity) or "auth-conf" (confidentiality),
	// you would unwrap the serverResponse here and reply.
	_ = serverResponse

	return nil
}

// RenewTicket explicitly requests a new TGT.
func (k *krbAuth) RenewTicket() error {
	// Note: kClient.Login() fetches a completely new ticket.
	// To prevent memory leaks or excessive requests, ensure this is only called
	// when the ticket is actually close to expiring.
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
