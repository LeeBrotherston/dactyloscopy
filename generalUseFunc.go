package tlsfingerprinting

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// check is a (probably over) simple function to wrap errors that will always be fatal
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// Take any number of formats (0x057843574835743, 0x00 0x01 0x00, 5847358943) in hex format,
// and convert to a byte array.
func hexStrToByteArray(s string) []byte {
	// Remove all the '0x's
	temp := strings.Replace(s, `0x`, ``, -1)

	// Remove all the spaces
	temp = strings.Replace(temp, ` `, ``, -1)

	// Now it should just be a long hex value.  Which we can convert to a byte array
	output, _ := hex.DecodeString(temp)

	return output
}

// HexNormalise is for converting 0x00 to 00FFAABB44, etc.  Also yes normalise, English :)
func HexNormalise(s string) string {
	var output string
	something := strings.Split(s, " ")

	for _, stuff := range something {
		if len(stuff) > 2 && stuff[0:2] == "0x" {
			temp := stuff[2:]
			output = output + string(temp)
		} else {
			output = s
		}
	}

	return strings.ToLower(output)
}

// UnpadStr removes pairs of '15' at even spacing from a str
func UnpadStr(s string) string {
	var output string
	var i = 0

	for ; i < len(s); i += 2 {
		if s[i] == 0x31 && s[i+1] == 0x35 {
			fmt.Printf("Unpadding...\n")
		} else {
			output = output + string(s[i]) + string(s[i+1])
		}
	}
	return output
}

// deGrease will remove grease from the provided input and will return the
// number of times it was degreased as well as the degreased bytes
func deGrease(s []byte) (int, []byte) {
	// Grease values (which are actually doubled)
	greaseValues := map[uint8]bool{
		0x0A: true,
		0x1A: true,
		0x2A: true,
		0x3A: true,
		0x4A: true,
		0x5A: true,
		0x6A: true,
		0x7A: true,
		0x8A: true,
		0x9A: true,
		0xAA: true,
		0xBA: true,
		0xCA: true,
		0xDA: true,
		0xEA: true,
		0xFA: true,
	}

	greaseCount := 0
	for count := 0; count < len(s); count += 2 {
		if s[count] == s[count+1] {
			// So it's a duplicate, but is it the *right* duplicate?!
			if greaseValues[s[count]] {
				greaseCount++
			}
		}
	}

	// OK let's construct the new version of the string (if needed)
	// did not do this above on the assumption that this is rare'ish
	// and so constructing after is more resource-efficient
	greaseless := make([]byte, len(s)-(greaseCount*2))

	if greaseCount > 0 {
		// count is safe to reuse now
		x := 0
		for count := 0; count < len(s); count += 2 {
			if s[count] == s[count+1] {
				if greaseValues[s[count]] {
					// Nothing right now
				} else {
					greaseless[x] = s[count]
					greaseless[x+1] = s[count+1]
					x += 2
				}
			} else {
				greaseless[x] = s[count]
				greaseless[x+1] = s[count+1]
				x += 2
			}
		}
		return greaseCount, greaseless
	}
	return 0, s
}

// hashFP is used to hash whole fingerprints into a single string based hash
func hashFP() {
	//something := "arse"
	//thing := murmur3.Sum64(something)
}
