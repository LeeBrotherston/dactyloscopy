package interceptls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	interceptls "github.com/leebrotherston/dactyloscopy/inteceptls"
	"github.com/stretchr/testify/require"
)

func TestInterceptListener_CapturesJA3(t *testing.T) {
	testCert, testKey, err := generateSelfSignedCert(t)
	require.NoError(t, err)
	require.NotEmpty(t, testCert)
	require.NotEmpty(t, testKey)

	cert, err := tls.X509KeyPair([]byte(testCert), []byte(testKey))
	require.NoError(t, err)

	// Prepare TLS config and custom listener
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	wrapped := interceptls.NewInterceptListener(ln, tlsConf)

	// Start dummy server with HTTP handler that exposes JA3
	server := &http.Server{
		ConnContext: interceptls.ConnContextHandler,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fp := interceptls.GetFingerprintFromRequest(w, r)
			require.NotEmpty(t, fp.JA3)
			w.Write([]byte(fp.JA3))
		}),
	}

	go server.Serve(wrapped)
	defer server.Close()

	// Create a real TLS client
	rootCAs := x509.NewCertPool()
	ok := rootCAs.AppendCertsFromPEM([]byte(testCert))
	require.True(t, ok)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Because we use self-signed cert
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://" + ln.Addr().String())
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte, err error) {
	t.Helper()
	log.Printf("Generating self-signed certificate...")
	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour), // Valid for 1 day

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: []string{"localhost"},
	}

	// Create the cert
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the cert
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// PEM encode the private key
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
