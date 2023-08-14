package dactyloscopy

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// TLSFingerprint finds the fingerprint that is matched by the provided packet
func (f *Fingerprint) ProcessClientHello(buf []byte) error {
	var (
		uint8Skipsize uint8
	)

	// The minimum may be longer, but shorter than this is definitely a problem ;)
	if len(buf) < 47 {
		return fmt.Errorf("packet appears to be truncated")
	}

	// This is a very quick and dirty acid test for is this a TLS client hello packet.
	// The "science" behind it is here:
	// https://speakerdeck.com/leebrotherston/stealthier-attacks-and-smarter-defending-with-tls-fingerprinting?slide=31
	// buf[0] == TLS Handshake buf[5] == Client Hello buf[1] == Record TLS Version
	// buf[9] == TLS Version
	if !(buf[0] == 22 && buf[5] == 1 && buf[1] == 3 && buf[9] == 3) {
		return fmt.Errorf("does not look like a client hello")
	}

	// Sweet, looks like a client hello, let's do some pre-processing
	clientHello := cryptobyte.String(buf)
	if !clientHello.ReadUint8(&f.MessageType) {
		return fmt.Errorf("could not read message type")
	}

	if !clientHello.ReadUint16((*uint16)(&f.RecordTLSVersion)) {
		return fmt.Errorf("could not read RecordTLS version")
	}

	// Length, handshake type, and length again
	clientHello.Skip(6)

	if !clientHello.ReadUint16((*uint16)(&f.TLSVersion)) {
		return fmt.Errorf("could not read TLS version")
	}

	// Random
	clientHello.Skip(32)

	// SessionID
	clientHello.ReadUint8(&uint8Skipsize)
	clientHello.Skip(int(uint8Skipsize))

	//if !clientHello.ReadUint16LengthPrefixed((*cryptobyte.String)(&ciphersuites)) {
	if !clientHello.ReadUint16LengthPrefixed(&f.rawSuites) {
		return fmt.Errorf("could not read ciphersuites")
	}

	// See if the packet contains any "grease" ciphersuites, which a) we wish to note
	// and b) we wish to filter out as it will make fingerprints look different (potentially)
	// as grease patterns are randomized by some clients.
	//thisFingerprint.AddCipherSuites(ciphersuites)
	err := f.suiteVinegar()
	if err != nil {
		return err
	}

	var (
		compression     cryptobyte.String
		compressionItem uint8
	)
	if !clientHello.ReadUint8LengthPrefixed(&compression) {
		return fmt.Errorf("could not read compression")
	}

	for !compression.Empty() {
		compression.ReadUint8(&compressionItem)
		f.Compression = append(f.Compression, compressionItem)
	}

	// And now to the really exciting world of extensions.... extensions!!!
	// Get me them thar extensions!!!!

	if !clientHello.ReadUint16LengthPrefixed(&f.rawExtensions) {
		return fmt.Errorf("could not read extensions")
	}

	err = f.addExtList()
	if err != nil {
		return err
	}

	return nil
}

// suiteVinegar removes grease from the ciphersuites 😜
func (f *Fingerprint) suiteVinegar() error {
	var (
		ciphersuite uint16
	)

	for !f.rawSuites.Empty() {
		if !f.rawSuites.ReadUint16(&ciphersuite) {
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

func (f *Fingerprint) addExtList() error {
	var (
		err error
	)
	for !f.rawExtensions.Empty() {
		var (
			extensionType uint16
			extContent    cryptobyte.String
		)
		//fmt.Printf("DEBUG: %v\n", f.rawExtensions)

		if !f.rawExtensions.ReadUint16(&extensionType) {
			return fmt.Errorf("could not read extension type")
		}

		if !f.rawExtensions.ReadUint16LengthPrefixed(&extContent) {
			return fmt.Errorf("could not read extension content")
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
				sni      cryptobyte.String
				hostname cryptobyte.String
				sniType  uint8
			)

			if !extContent.ReadUint16LengthPrefixed(&sni) {
				return fmt.Errorf("could not read SNI")
			}

			if !sni.ReadUint8(&sniType) {
				return fmt.Errorf("could not read SNI type")
			}

			// Host Type, hopefully.... ever seen any other? :)
			if sniType == 0 {
				sni.ReadUint16LengthPrefixed(&hostname)
			} else {
				sni.ReadUint16LengthPrefixed(nil)
			}
			f.SNI = string(hostname)
			f.Extensions = append(f.Extensions, extensionType)

		// The various "lists of stuff" extensions :)
		case 0x0015:
			// Padding
			fmt.Printf("%v\n", skip16(extContent))
			f.Extensions = append(f.Extensions, extensionType)

		case 0x000a:
			// ellipticCurves
			fmt.Printf("%v\n", read16Length16Pair(extContent, &f.ECurves))
			f.Extensions = append(f.Extensions, extensionType)

		case 0x000b:
			// ecPoint formats
			fmt.Printf("%v\n", read16Length8Pair(extContent, &f.EcPointFmt))
			f.Extensions = append(f.Extensions, extensionType)

		case 0x000d:
			// Signature algorithms
			fmt.Printf("%v\n", read16Length16Pair(extContent, &f.SigAlg))
			f.Extensions = append(f.Extensions, extensionType)

		case 0x002b:
			// Supported versions (new in TLS 1.3... I think)
			fmt.Printf("%v\n", read16Length16Pair(extContent, &f.SupportedVersions))
			f.Extensions = append(f.Extensions, extensionType)

		default:
			//fmt.Printf("Unused extension: %d\n", extensionType)
			fmt.Printf("%v\n", skip16(extContent))
			f.Extensions = append(f.Extensions, extensionType)
		}
	}

	f.JA3, err = hashMD5(fmt.Sprintf("%d,%s,%s,%s,%s", f.TLSVersion, sliceToDash16(f.Ciphersuite), sliceToDash16(f.Extensions), sliceToDash16(f.ECurves), sliceToDash8(f.EcPointFmt)))
	if err != nil {
		return err
	}
	return nil
}

func (f *Fingerprint) MakeHashes() error {
	return nil
}

func hashMD5(text string) (string, error) {
	hasher := md5.New()
	_, err := hasher.Write([]byte(text))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
