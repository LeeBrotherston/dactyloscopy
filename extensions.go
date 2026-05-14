package dactyloscopy

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

func (f *Fingerprint) handleExtension(extensionType uint16, extContent cryptobyte.String) error {

	// This is the extensionType again, but to add to the extensions var for fingerprinting
	switch extensionType {
	case ExtServerName:
		// SNI handling
		var (
			sni      cryptobyte.String
			hostname cryptobyte.String
			sniType  uint16
		)

		if !extContent.ReadUint16LengthPrefixed(&sni) {
			return fmt.Errorf("could not read SNI")
		}

		if !sni.ReadUint16(&sniType) {
			return fmt.Errorf("could not read SNI type, sni=[%X], context=[%X]", sni, extContent)
		}

		// Host Type, hopefully.... ever seen any other? :)
		if sniType == 0 {
			sni.ReadUint8LengthPrefixed(&hostname)
		} else {
			var nullOut cryptobyte.String
			sni.ReadUint8LengthPrefixed(&nullOut)
			fmt.Printf("Weird?! [%X] [%X]\n", sniType, nullOut)
		}
		f.SNI = string(hostname)
		f.Extensions = append(f.Extensions, extensionType)

	case ExtPadding:
		// Padding handling
		err := skip16(extContent)
		if err != nil {
			return fmt.Errorf("could not read extension padding, err=[%w]", err)
		}
	case ExtEllipticCurves:
		// ellipticCurves
		err := read16Length16Pair(&extContent, &f.ECurves)
		if err != nil {
			return fmt.Errorf("could not read ellipticCurves extension, err=[%w]", err)
		}
		f.Extensions = append(f.Extensions, extensionType)

	case ExtECPointFormats:
		// ecPoint formats
		var out []uint64
		err := readXLengthYVal(&extContent, &out, 1, 1)
		if err != nil {
			return fmt.Errorf("could not read ecPoint extension, err=[%w]", err)
		}
		for _, y := range out {
			f.EcPointFmt = append(f.EcPointFmt, uint8(y))
		}
		f.Extensions = append(f.Extensions, extensionType)

	case ExtSignatureAlgorithms:
		// S
		err := read16Length16Pair(&extContent, &f.SigAlg)
		if err != nil {
			return fmt.Errorf("could not read signature algorithms extension, err=[%w]", err)
		}
		f.Extensions = append(f.Extensions, extensionType)

	case ExtSupportedVersions:
		// Supported versions
		err := read8Length16Pair(&extContent, &f.SupportedVersions)
		if err != nil {
			return fmt.Errorf("could not read supported versions extension, err=[%w]", err)
		}
		f.Extensions = append(f.Extensions, extensionType)

	case ExtALPN:
		// ALPN (Application-Layer Protocol Negotiation)
		var alpnList cryptobyte.String
		if !extContent.ReadUint16LengthPrefixed(&alpnList) {
			return fmt.Errorf("could not read ALPN protocol list")
		}
		for !alpnList.Empty() {
			var proto cryptobyte.String
			if !alpnList.ReadUint8LengthPrefixed(&proto) {
				return fmt.Errorf("could not read ALPN protocol name")
			}
			f.ALPNProtocols = append(f.ALPNProtocols, string(proto))
		}
		f.Extensions = append(f.Extensions, extensionType)

	// KeyShare (0x0033)
	case 0x0033:
		// TLS 1.3 KeyShare extension
		var keyShareList cryptobyte.String
		if !extContent.ReadUint16LengthPrefixed(&keyShareList) {
			return fmt.Errorf("could not read key share list")
		}
		for !keyShareList.Empty() {
			var group uint16
			if !keyShareList.ReadUint16(&group) {
				return fmt.Errorf("could not read key share group")
			}
			// Skip key_exchange length and value
			var keyEx cryptobyte.String
			if !keyShareList.ReadUint16LengthPrefixed(&keyEx) {
				return fmt.Errorf("could not read key exchange value")
			}
			f.KeyShareGroups = append(f.KeyShareGroups, group)
		}
		f.Extensions = append(f.Extensions, extensionType)

	// PSK Key Exchange Modes (0x002d)
	case 0x002d:
		var modes cryptobyte.String
		if !extContent.ReadUint8LengthPrefixed(&modes) {
			return fmt.Errorf("could not read PSK key exchange modes")
		}
		for !modes.Empty() {
			var mode uint8
			if !modes.ReadUint8(&mode) {
				return fmt.Errorf("could not read PSK key exchange mode")
			}
			f.PSKKeyExchangeModes = append(f.PSKKeyExchangeModes, mode)
		}
		f.Extensions = append(f.Extensions, extensionType)

	// Cookie (0x002c)
	case 0x002c:
		var cookie cryptobyte.String
		if !extContent.ReadUint16LengthPrefixed(&cookie) {
			return fmt.Errorf("could not read cookie value")
		}
		f.Cookie = string(cookie)
		f.Extensions = append(f.Extensions, extensionType)

	// Renegotiation Info (0xff01)
	case 0xff01:
		var reneg cryptobyte.String
		if !extContent.ReadUint8LengthPrefixed(&reneg) {
			return fmt.Errorf("could not read renegotiation info")
		}
		f.RenegotiationInfo = string(reneg)
		f.Extensions = append(f.Extensions, extensionType)

	// SessionTicket (0x0023)
	case 0x0023:
		// SessionTicket is just a length-prefixed blob
		f.SessionTicketLen = len(extContent)
		f.Extensions = append(f.Extensions, extensionType)

	default:
		// Append this list first as there are 0-length extensions
		f.Extensions = append(f.Extensions, extensionType)

		var unknownExt []uint8
		if len(extContent) <= 1 {
			// empty extension, that we can't read the inner length from, because empty
			return nil
		}

		err := read16Length8Pair(&extContent, &unknownExt)
		if err != nil {
			return fmt.Errorf("could not read unknown extension, type=[%X] ianaName=[%s], err=[%s]", extensionType, GetIANAExtension(extensionType), err)
		}
	}
	return nil
}
