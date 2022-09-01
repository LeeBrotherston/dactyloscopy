package dactyloscopy

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// TLSFingerprint finds the fingerprint that is matched by the provided packet
func (f *Fingerprint) ProcessClientHello(buf []byte, fingerprintDBNew map[uint64]string) error {
	var (
		thisFingerprint Fingerprint
		uint8Skipsize   uint8
		ciphersuites    cryptobyte.String
		extensionBlock  cryptobyte.String
	)

	// The minimum may be longer, but shorter than this is definitely a problem ;)
	if len(buf) < 47 {
		return fmt.Errorf("packet appears to be truncated")
	}

	// This is the Lee acid test for is this a TLS client hello packet The "science"
	// behind it is here:
	// https://speakerdeck.com/leebrotherston/stealthier-attacks-and-smarter-defending-with-tls-fingerprinting?slide=31
	// buf[0] == TLS Handshake buf[5] == Client Hello buf[1] == Record TLS Version
	// buf[9] == TLS Version
	if !(buf[0] == 22 && buf[5] == 1 && buf[1] == 3 && buf[9] == 3) {
		return fmt.Errorf("does not look like a client hello")
	}

	// Sweet, looks like a client hello, let's do some pre-processing
	clientHello := cryptobyte.String(buf)
	if !clientHello.ReadUint8(&thisFingerprint.MessageType) {
		return fmt.Errorf("could not read message type")
	}

	if !clientHello.ReadUint8((*uint8)(&thisFingerprint.RecordTLSVersion)) {
		return fmt.Errorf("could not read RecordTLS version")
	}

	if !clientHello.ReadUint8((*uint8)(&thisFingerprint.TLSVersion)) {
		return fmt.Errorf("could not read TLS version")
	}

	if !clientHello.ReadUint8(&uint8Skipsize) {
		return fmt.Errorf("could not skip random")
	}
	if !clientHello.Skip(int(uint8Skipsize)) {
		return fmt.Errorf("could not skip random")
	}

	if !clientHello.ReadUint16LengthPrefixed((*cryptobyte.String)(&ciphersuites)) {
		return fmt.Errorf("could not read ciphersuites")
	}

	// See if the packet contains any "grease" ciphersuites, which a) we wish to note
	// and b) we wish to filter out as it will make fingerprints look different (potentially)
	// as grease patterns are randomized by some clients.
	thisFingerprint.AddCipherSuites(ciphersuites)

	if !clientHello.ReadUint8LengthPrefixed(&thisFingerprint.Compression) {
		return nil
	}

	// And now to the really exciting world of extensions.... extensions!!!
	// Get me them thar extensions!!!!

	if !clientHello.ReadUint16LengthPrefixed(&extensionBlock) {
		return nil
	}
	thisFingerprint.AddExtList(extensionBlock)

	return nil
}

func (f *Fingerprint) AddCipherSuites(ciphersuites cryptobyte.String) error {
	var (
		ciphersuite uint16
	)

	for !ciphersuites.Empty() {
		if !ciphersuites.ReadUint16(&ciphersuite) {
			return fmt.Errorf("could not load ciphersuites")
		}
		// This is the extensionType again, but to add to the extensions var for fingerprinting
		switch uint16(ciphersuite) {
		// Lets not add grease to the extension list....
		case 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
			0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
			0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA,
			0xFAFA:
			f.Grease = true
		// Or padding, because it's padding.....
		case 0x0015:
		// But everything else is fine
		default:
			f.Ciphersuite = append(f.Ciphersuite, ciphersuite)
		}
	}
	return nil
}

func (f *Fingerprint) AddExtList(extBlock cryptobyte.String) error {
	for !extBlock.Empty() {
		var (
			uint16Skipsize uint16
			extensionType  uint16
			extContent     cryptobyte.String
		)

		if !extBlock.ReadUint16(&extensionType) || !extBlock.ReadUint16LengthPrefixed(&extContent) {
			return fmt.Errorf("could not read extension")
		}

		// This is the extensionType again, but to add to the extensions var for fingerprinting
		switch uint16(extensionType) {
		// Lets not add grease to the extension list....
		case 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
			0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
			0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA,
			0xFAFA:
			f.Grease = true
			// But everything else is fine

		case 0x0000:
			// SNI
			var (
				sni     cryptobyte.String
				sniType uint8
			)

			if !extContent.ReadUint16LengthPrefixed(&sni) || !extContent.ReadUint8(&sniType) {
				return fmt.Errorf("could not read SNI")
			}

			// Host Type, hopefully.... ever seen any other? :)
			if sniType == 0 {
				sni.ReadUint16LengthPrefixed(&f.SNI)
			} else {
				sni.ReadUint16LengthPrefixed(nil)
			}
			f.Extensions = append(f.Extensions, extensionType)

		case 0x0015:
			// Padding
			if !extContent.ReadUint16(&uint16Skipsize) || extContent.Skip(int(uint16Skipsize)) {
				return fmt.Errorf("could not skip padding")
			}
			f.Extensions = append(f.Extensions, extensionType)

		case 0x000a:
			// ellipticCurves
			var (
				curveBlock cryptobyte.String
			)
			if !extContent.ReadUint16LengthPrefixed(&curveBlock) || !curveBlock.ReadUint16LengthPrefixed(&f.ECurves) {
				return fmt.Errorf("could not read elliptic curves")
			}
			f.Extensions = append(f.Extensions, extensionType)

		case 0x000b:
			// ecPoint formats
			var (
				ecPointBlock cryptobyte.String
			)
			if !extContent.ReadUint16LengthPrefixed(&ecPointBlock) || !ecPointBlock.ReadUint16LengthPrefixed(&f.EcPointFmt) {
				return fmt.Errorf("could not read ecPoint format")
			}
			f.Extensions = append(f.Extensions, extensionType)

		case 0x000d:
			// Signature algorithms
			var (
				signatureAlgoBlock cryptobyte.String
			)
			if !extContent.ReadUint16LengthPrefixed(&signatureAlgoBlock) || !signatureAlgoBlock.ReadUint16LengthPrefixed(&f.SigAlg) {
				return fmt.Errorf("could not read ecPoint format")
			}
			f.Extensions = append(f.Extensions, extensionType)

		case 0x002b:
			// Supported versions (new in TLS 1.3... I think)
			var (
				supportedVersionsBlock cryptobyte.String
			)
			if !extContent.ReadUint16LengthPrefixed(&supportedVersionsBlock) || !supportedVersionsBlock.ReadUint16LengthPrefixed(&f.SupportedVersions) {
				return fmt.Errorf("could not read supported versions")
			}
			f.Extensions = append(f.Extensions, extensionType)

		default:
			if !extContent.ReadUint16(&uint16Skipsize) || !extContent.Skip(int(uint16Skipsize)) {
				return fmt.Errorf("could not read extension")
			}
			f.Extensions = append(f.Extensions, extensionType)
		}
	}
	return nil
}

func (f *Fingerprint) MakeHashes() error {
	return nil
}
