package main

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
	"time"

	"github.com/gin-gonic/gin"
	interceptls "github.com/leebrotherston/dactyloscopy/inteceptls"
)

// === Main ===

func main() {
	testCertPEM, testKeyPEM, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("failed to generate self-signed cert: %v", err)
	}

	cert, err := tls.X509KeyPair([]byte(testCertPEM), []byte(testKeyPEM))
	if err != nil {
		log.Fatalf("invalid cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	router := gin.New()

	router.GET("/", func(c *gin.Context) {
		hello := interceptls.GetFingerprintFromContext(c.Request.Context())
		c.JSON(200, gin.H{"tls_sni": hello.SNI})
	})

	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Handler:     router,
		ConnContext: interceptls.ConnContextHandler,
	}

	log.Printf("Listening on https://%s", ln.Addr().String())
	listener := interceptls.NewInterceptListener(ln, tlsConfig)
	err = server.Serve(listener)
	log.Fatal(err)
}

// === Dummy Self-signed Certificate ===
// Replace with your own for real use

func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
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
