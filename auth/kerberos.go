package auth

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

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
	tkt, sessionKey, err := k.kClient.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("failed to get service ticket for %s: %w", spn, err)
	}

	// 1a. Create the Authenticator
	auth, err := types.NewAuthenticator(k.kClient.Credentials.Realm(), k.kClient.Credentials.CName())
	if err != nil {
		return fmt.Errorf("failed to create authenticator: %w", err)
	}

	// 1b. Generate the AP-REQ
	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return fmt.Errorf("failed to create AP-REQ: %w", err)
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return err
	}

	oid := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}
	gssapiToken := append([]byte{0x60}, encodeLength(len(oid)+len(apReqBytes))...)
	gssapiToken = append(gssapiToken, oid...)
	gssapiToken = append(gssapiToken, apReqBytes...)

	if err := writeToken(conn, gssapiToken); err != nil {
		return fmt.Errorf("failed to send GSSAPI token: %w", err)
	}

	_, err = readToken(conn)
	if err != nil {
		return fmt.Errorf("failed to read AP-REP: %w", err)
	}

	_, err = readToken(conn)
	if err != nil {
		return fmt.Errorf("failed to read QoP challenge: %w", err)
	}

	qopResponse := []byte{0x01, 0x00, 0x00, 0x00}
	if err := writeToken(conn, qopResponse); err != nil {
		return fmt.Errorf("failed to write QoP response: %w", err)
	}

	return nil
}

func (k *krbAuth) Close() {
	if k.kClient != nil {
		k.kClient.Destroy()
	}
}

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
	token := make([]byte, length)
	_, err := io.ReadFull(conn, token)
	return token, err
}

func encodeLength(length int) []byte {
	if length <= 127 {
		return []byte{byte(length)}
	}
	var buf bytes.Buffer
	for length > 0 {
		buf.WriteByte(byte(length & 0xff))
		length >>= 8
	}
	b := buf.Bytes()
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}
