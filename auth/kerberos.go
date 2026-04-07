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
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosClient defines the interface for HBase authentication.
type KerberosClient interface {
	PerformSASLHandshake(ctx context.Context, conn net.Conn, spn string) error
	Close()
}

type krbAuth struct {
	kClient *client.Client
}

// NewKerberosClient initializes the gokrb5 client from a keytab.
func NewKerberosClient(krb5ConfPath, keytabPath, principal, realm string) (KerberosClient, error) {
	cfg, err := config.Load(krb5ConfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load krb5.conf: %w", err)
	}

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load keytab: %w", err)
	}

	kClient := client.NewWithKeytab(principal, realm, kt, cfg)
	if err := kClient.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login failed: %w", err)
	}

	return &krbAuth{kClient: kClient}, nil
}

func (k *krbAuth) PerformSASLHandshake(ctx context.Context, conn net.Conn, spn string) error {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	fmt.Println(">>>> RUNNING PERFECT GSSAPI & QoP PING-PONG <<<<")

	// 1. Get the Service Ticket and Session Key
	tkt, sessionKey, err := k.kClient.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("failed to get service ticket for %s: %w", spn, err)
	}

	// 2. Generate a fully-formed GSSAPI AP-REQ Token (automatically includes 0x8003 Checksum & framing)
	gssapiFlags := []int{gssapi.ContextFlagMutual, gssapi.ContextFlagReplay, gssapi.ContextFlagInteg}
	krb5Token, err := spnego.NewKRB5TokenAPREQ(k.kClient, tkt, sessionKey, gssapiFlags, []int{})
	if err != nil {
		return fmt.Errorf("failed to create KRB5 GSSAPI token: %w", err)
	}

	apReqBytes, err := krb5Token.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal KRB5 GSSAPI token: %w", err)
	}

	// 3. Send the perfect GSSAPI token to HBase
	if err := writeToken(conn, apReqBytes); err != nil {
		return fmt.Errorf("failed to send GSSAPI token: %w", err)
	}

	// 4. Handle the Hadoop SASL Ping-Pong Exchange
	for {
		resp, err := readToken(conn)
		if err != nil {
			return fmt.Errorf("failed to read from server: %w", err)
		}

		if len(resp) == 0 {
			continue
		}

		// Try to parse the response as a QoP Challenge (WrapToken)
		var serverQoP gssapi.WrapToken
		if err := serverQoP.Unmarshal(resp, true); err == nil {

			// It IS a WrapToken! Verify it using our session key.
			if _, err := serverQoP.Verify(sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
				return fmt.Errorf("failed to verify server QoP challenge: %w", err)
			}

			// Wrap and Send Client QoP Response
			// We echo back the server's payload to accept the parameters (auth only)
			clientQoP, err := gssapi.NewInitiatorWrapToken(serverQoP.Payload, sessionKey)
			if err != nil {
				return fmt.Errorf("failed to create client QoP response: %w", err)
			}

			clientQoPBytes, err := clientQoP.Marshal()
			if err != nil {
				return fmt.Errorf("failed to marshal client QoP response: %w", err)
			}

			if err := writeToken(conn, clientQoPBytes); err != nil {
				return fmt.Errorf("failed to write client QoP response: %w", err)
			}

			// Handshake complete! HBase will now accept standard RPC calls.
			return nil
		}

		// If we couldn't unmarshal it as a WrapToken, it is the AP-REP (Mutual Auth response).
		// In Hadoop RPC, the client MUST send an empty byte array back to the server
		// to acknowledge the AP-REP and trigger the server to send the QoP Challenge.
		if err := writeToken(conn, []byte{}); err != nil {
			return fmt.Errorf("failed to send empty token to trigger QoP: %w", err)
		}
	}
}

func (k *krbAuth) Close() {
	if k.kClient != nil {
		k.kClient.Destroy()
	}
}

// --- Helpers ---

func writeToken(conn net.Conn, token []byte) error {
	buf := make([]byte, 4+len(token))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(token)))
	copy(buf[4:], token)
	_, err := conn.Write(buf)
	return err
}

func readToken(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length == 0 {
		return []byte{}, nil
	}

	token := make([]byte, length)
	_, err := io.ReadFull(conn, token)
	return token, err
}
