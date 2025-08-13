package dactyloscopy

const (
	// Configuration Constants
	minPacketLength = 45 // Theoretical minimum size of smallest TLS header (TLSv1.0)

	// TLS Extension types
	ExtServerName          uint16 = 0x0000
	ExtEllipticCurves      uint16 = 0x000a
	ExtECPointFormats      uint16 = 0x000b
	ExtSignatureAlgorithms uint16 = 0x000d
	ExtALPN                uint16 = 0x0010
	ExtSupportedVersions   uint16 = 0x002b
	ExtPadding             uint16 = 0x0015

	// TLS Protocol Versions
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// Common GREASE values used by clients
var GreaseValues = []uint16{
	0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
	0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
	0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA,
	0xFAFA,
}
