package dactyloscopy

import "golang.org/x/crypto/cryptobyte"

// Fingerprint management... almost the same as fingerprintFile.  maybe
// they can be combined in the future.
type Fingerprint struct {
	Id                float64 //`json:"id"`
	Desc              string  //`json:"desc"`
	MessageType       uint8
	RecordTLSVersion  uint8             //`json:"record_tls_version"`
	TLSVersion        uint8             //`json:"tls_version"`
	Ciphersuite       []uint16          //`json:"ciphersuite"`
	Compression       cryptobyte.String //`json:"compression"`
	Extensions        []uint16          //`json:"extensions"`
	ECurves           cryptobyte.String //`json:"e_curves"`
	SigAlg            cryptobyte.String //`json:"sig_alg"`
	EcPointFmt        cryptobyte.String //`json:"ec_point_fmt"`
	Grease            bool
	SupportedVersions cryptobyte.String
	Hash              uint64
	SNI               cryptobyte.String
}
