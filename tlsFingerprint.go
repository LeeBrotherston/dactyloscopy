package dactyloscopy

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	// "slices" // removed unused import

	"golang.org/x/crypto/cryptobyte"
)

// Constants for TLS message types and versions
const (
	HandshakeType    uint8 = 22
	ClientHelloMsg   uint8 = 1
	RecordTLSVersion       = 3
	TLSVersion             = 3
)

// ProcessClientHello processes the client hello packet and returns a Fingerprint
func ProcessClientHello(buf []byte) (*Fingerprint, error) {
	var fp Fingerprint
	err := fp.ProcessClientHello(buf)
	if err != nil {
		return nil, err
	}
	return &fp, nil
}

// ProcessClientHello processes the client hello packet and returns a Fingerprint
func (f *Fingerprint) ProcessClientHello(buf []byte) error {
	if err := IsClientHello(buf); err != nil {
		return fmt.Errorf("doesn't look like a client hello packet: %w", err)
	}

	clientHello := cryptobyte.String(buf)
	if err := f.parseClientHello(&clientHello); err != nil {
		return fmt.Errorf("parsing client hello: %w", err)
	}

	if err := f.generateJA3(); err != nil {
		return fmt.Errorf("error generating JA3: %w", err)
	}

	if err := f.generateJA4(); err != nil {
		return fmt.Errorf("error generating JA4: %w", err)
	}

	return nil
}

// IsClientHello returns a (hopefully descriptive) error if the packet is not
// TLS, or nil if it is TLS.  Not a full parse, but a quick a dirty check to see
// if it is worth even attempting to parse
func IsClientHello(buf []byte) error {
	if len(buf) < minPacketLength {
		return fmt.Errorf("packet length %d is less than minimum %d", len(buf), minPacketLength)
	}

	// Quick acid test for TLS client hello packet
	if !(buf[0] == HandshakeType &&
		buf[5] == ClientHelloMsg &&
		buf[1] == RecordTLSVersion &&
		buf[9] == TLSVersion) {
		return fmt.Errorf("invalid TLS client hello format")
	}

	return nil
}

func (f *Fingerprint) parseClientHello(clientHello *cryptobyte.String) error {
	var (
		uint8Skipsize uint8
	)
	start := clientHello

	if !clientHello.ReadUint8(&f.MessageType) {
		return fmt.Errorf("could not read message type")
	}

	if !clientHello.ReadUint16((*uint16)(&f.RecordTLSVersion)) {
		return fmt.Errorf("could not read RecordTLS version")
	}

	// Length, handshake type, and length again
	if !clientHello.Skip(6) {
		return fmt.Errorf("could not skip over lenth and handshake type")
	}

	if !clientHello.ReadUint16((*uint16)(&f.TLSVersion)) {
		return fmt.Errorf("could not read TLS version")
	}

	// Random
	var entropy []byte
	if !clientHello.ReadBytes(&entropy, 32) {
		//if !clientHello.Skip(32) {
		return fmt.Errorf("could not skip over entropy")
	}

	// SessionID
	if !clientHello.ReadUint8(&uint8Skipsize) {
		return fmt.Errorf("could not read session id size")
	}
	if uint8Skipsize > 0 {
		if !clientHello.Skip(int(uint8Skipsize)) {
			return fmt.Errorf("could not skip over session id, progress=[%d/%d]", start, clientHello)
		}
	}

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
	err = read16Length8Pair(clientHello, (*[]uint8)(&f.rawExtensions))
	if err != nil {
		return fmt.Errorf("could not copy extensions section")
	}
	/*
		if !clientHello.ReadUint16LengthPrefixed(&f.rawExtensions) {
			return fmt.Errorf("could not read extensions section")
		}
	*/

	err = f.addExtList()
	if err != nil {
		return err
	}

	return nil
}

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
		//case 0x0015:
		// But everything else is fine
		default:
			f.Ciphersuite = append(f.Ciphersuite, ciphersuite)
		}
	}
	return nil
}

func (f *Fingerprint) addExtList() error {
	for !f.rawExtensions.Empty() {
		var (
			extensionType uint16
			extContent    cryptobyte.String
			//extContentBytes []uint8
		)

		// Extension Type
		if !f.rawExtensions.ReadUint16(&extensionType) {
			return fmt.Errorf("could not read extension type, raw=[%X]", f.rawExtensions)
		}

		if !f.rawExtensions.ReadUint16LengthPrefixed(&extContent) {
			return fmt.Errorf("looks like a truncated packet (fragmented?), for type=[%X:%s]", extensionType, GetIANAExtension(extensionType))
		}

		err := f.handleExtension(extensionType, extContent)
		if err != nil {
			return err
		}
	}

	// The official JA3 libraries seem to use 0 when EcPointFmt is empty instead
	// of leaving the field blank, so we will do this to remain compatible
	if len(f.EcPointFmt) == 0 {
		f.EcPointFmt = append(f.EcPointFmt, 0)
	}
	return nil
}

func (f *Fingerprint) generateJA3() error {
	// JA3 spec is : SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
	unhashed := fmt.Sprintf("%d,%s,%s,%s,%s",
		f.TLSVersion,
		sliceToDash16(f.Ciphersuite),
		sliceToDash16(f.Extensions),
		sliceToDash16(f.ECurves),
		sliceToDash8(f.EcPointFmt))

	hasher := md5.New()
	if _, err := hasher.Write([]byte(unhashed)); err != nil {
		return fmt.Errorf("calculating hash: %w", err)
	}
	//fmt.Printf("unhashed JA3: %s\n", unhashed)
	f.JA3 = hex.EncodeToString(hasher.Sum(nil))
	return nil
}

func (f *Fingerprint) generateJA4() error {
	// JA4: t<version><sni><cipher count><ext count><alpn>,<ciphers>,<exts>,<alpn-list>
	JA4_a := "t"

	switch f.TLSVersion {
	case VersionTLS10:
		JA4_a += "10"
	case VersionTLS11:
		JA4_a += "11"
	case VersionTLS12:
		JA4_a += "12"
	case VersionTLS13:
		JA4_a += "13"
	default:
		JA4_a += "??"
	}

	sniPresent := false
	for _, ext := range f.Extensions {
		if ext == ExtServerName {
			sniPresent = true
			break
		}
	}
	if sniPresent {
		JA4_a += "d"
	} else {
		JA4_a += "i"
	}

	JA4_a += fmt.Sprintf("%02d%02d", len(f.Ciphersuite), len(f.Extensions))

	alpn := "-"
	if len(f.ALPNProtocols) > 0 {
		alpn = f.ALPNProtocols[0]
	}
	JA4 := JA4_a + alpn

	// Extended JA4: hash ciphers, extensions, and ALPN list as dash-separated values
	/*
		sort.Slice(f.Ciphersuite, func(i, j int) bool {
			return f.Ciphersuite[i] > f.Ciphersuite[j]
		})
	*/

	ciphers := sliceToDash16(f.Ciphersuite)
	extensions := sliceToDash16(f.Extensions)
	alpnList := "-"
	if len(f.ALPNProtocols) > 0 {
		alpnList = ""
		for i, proto := range f.ALPNProtocols {
			if i > 0 {
				alpnList += "-"
			}
			alpnList += proto
		}
	}

	ciphersHash, err := hashSHA256(ciphers)
	if err != nil {
		return err
	}
	extensionsHash, err := hashSHA256(extensions)
	if err != nil {
		return err
	}
	alpnHash := "-"
	if alpnList != "-" && alpnList != "" {
		alpnHash, _ = hashSHA256(alpnList)
	}
	// Final JA4 string: base + ,ciphers_sha256,extensions_sha256,alpn_sha256
	JA4 = fmt.Sprintf("%s,%s,%s,%s", JA4, ciphersHash, extensionsHash, alpnHash)

	f.JA4 = JA4
	return nil
}

// MakeHashes generates both JA3 and LB1 hashes from the fingerprint data
// If this method isn't needed, it should be removed since generateHashes()
// is already handling the JA3 hash generation
func (f *Fingerprint) MakeHashes() error {
	// Generate JA3 hash
	if err := f.generateJA3(); err != nil {
		return fmt.Errorf("generating JA3 hash: %w", err)
	}

	// Generate LB1 hash if needed
	// TODO: Implement LB1 hash generation if required
	// f.LB1 = ...

	return nil
}

func hashSHA256(text string) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(text))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
