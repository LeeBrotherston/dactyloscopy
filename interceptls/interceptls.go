package interceptls

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/LeeBrotherston/dactyloscopy"
)

// context key used for store/retrieve of client hello info
type contextKey string

const ClientHelloKey contextKey = "clientHelloInfo"

// Custom Conn
type HelloConn struct {
	net.Conn
	DactFP *dactyloscopy.Fingerprint
}

func (c *HelloConn) HelloFP() *dactyloscopy.Fingerprint {
	return c.DactFP
}

// Custom Listener
type inspectingListener struct {
	net.Listener
	tlsConfig *tls.Config
}

func ConnContextHandler(ctx context.Context, c net.Conn) context.Context {
	if hc, ok := c.(*HelloConn); ok {
		return context.WithValue(ctx, ClientHelloKey, hc.DactFP)
	}
	return ctx
}

func GetFingerprintFromRequest(w http.ResponseWriter, r *http.Request) dactyloscopy.Fingerprint {
	return GetFingerprintFromContext(r.Context())
}

func GetFingerprintFromContext(ctx context.Context) dactyloscopy.Fingerprint {
	if info, ok := ctx.Value(ClientHelloKey).(*dactyloscopy.Fingerprint); ok {
		return *info
	}
	return dactyloscopy.Fingerprint{}
}

func (l *inspectingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	peeked, err := peekClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("peekClientHello: %w", err)
	}

	parsedHello := parseClientHello(peeked)

	reader := io.MultiReader(bytes.NewReader(peeked), conn)
	wrapped := &readFirstConn{Conn: conn, Reader: reader}
	tlsConn := tls.Server(wrapped, l.tlsConfig)

	return &HelloConn{
		Conn:   tlsConn,
		DactFP: parsedHello,
	}, nil
}

type readFirstConn struct {
	net.Conn
	io.Reader
}

func (c *readFirstConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func peekClientHello(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}

	length := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	return append(hdr, body...), nil
}

func parseClientHello(data []byte) *dactyloscopy.Fingerprint {
	stuff := extractFP(data)
	return &stuff
}

func extractFP(data []byte) dactyloscopy.Fingerprint {
	var tlsfp dactyloscopy.Fingerprint
	err := tlsfp.ProcessClientHello(data)
	if err != nil {
		return dactyloscopy.Fingerprint{}
	}
	return tlsfp
}

func NewInterceptListener(listener net.Listener, tlsConfig *tls.Config) *inspectingListener {
	return &inspectingListener{Listener: listener, tlsConfig: tlsConfig}
}
