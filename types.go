package dactyloscopy

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Fingerprint represents a TLS client fingerprint including both JA3 and LB1 formats
type Fingerprint struct {
	MessageType       uint8    `json:"message_type"`
	RecordTLSVersion  uint16   `json:"record_tls_version"`
	TLSVersion        uint16   `json:"tls_version"`
	Ciphersuite       []uint16 `json:"ciphersuite"`
	Compression       []uint8  `json:"compression"`
	Extensions        []uint16 `json:"extensions"`
	ECurves           []uint16 `json:"e_curves"`
	SigAlg            []uint16 `json:"sig_alg"`
	EcPointFmt        []uint8  `json:"ec_point_fmt"`
	Grease            bool     `json:"grease"`
	SupportedVersions []uint16 `json:"supported_versions"`
	ALPNProtocols     []string `json:"alpn_protocols"`

	//LB1               string   `json:"lb1,omitempty"`
	JA3 string `json:"ja3,omitempty"`
	JA4 string `json:"ja4,omitempty"`
	SNI string `json:"sni,omitempty"`

	rawSuites     cryptobyte.String
	rawExtensions cryptobyte.String
}

// Validate checks if the fingerprint data is valid
func (f *Fingerprint) Validate() error {
	// Check required fields
	if f.MessageType != HandshakeType {
		return fmt.Errorf("invalid message type: %d", f.MessageType)
	}

	if len(f.Ciphersuite) == 0 {
		return fmt.Errorf("no ciphersuites present")
	}

	if len(f.Extensions) == 0 {
		return fmt.Errorf("no extensions present")
	}

	// Check version numbers are valid
	if f.TLSVersion == 0 {
		return fmt.Errorf("invalid TLS version")
	}

	return nil
}
