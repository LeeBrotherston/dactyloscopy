package dactyloscopy

import "golang.org/x/crypto/cryptobyte"

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
	LB1               string   `json:"lb1,omitempty"`
	JA3               string   `json:"ja3,omitempty"`
	SNI               string   `json:"sni,omitempty"`
	rawSuites         cryptobyte.String
	rawExtensions     cryptobyte.String
}
