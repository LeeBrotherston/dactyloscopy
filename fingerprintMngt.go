package dactyloscopy

import (
	"fmt"

	"github.com/spaolacci/murmur3"
)

// hash generates the hash of the FP, to be used in the FP lookup tables
func hash(myPrint Fingerprint) uint64 {
	hasher := murmur3.New64()
	// Throw the various values into the hashererererer
	hasher.Write([]byte(myPrint.Ciphersuite))
	hasher.Write([]byte(myPrint.Compression))
	hasher.Write([]byte(myPrint.EcPointFmt))
	hasher.Write([]byte(myPrint.ECurves))
	hasher.Write([]byte(myPrint.Extensions))
	if myPrint.Grease == true {
		hasher.Write([]byte("true"))
	} else {
		hasher.Write([]byte("false"))
	}
	hasher.Write([]byte(myPrint.RecordTLSVersion))
	hasher.Write([]byte(myPrint.SigAlg))
	hasher.Write([]byte(myPrint.TLSVersion))
	hasher.Write([]byte(myPrint.SupportedVersions))
	myHash := hasher.Sum64()
	return myHash
}

// ja3 is used to create the JA3 fingerprint format (which does not check as
// many fields and can be more easily spoofed, but... is more widely adopted)
// from the fingerprint. Info on this format here:
// https://github.com/salesforce/ja3
func ja3(myPrint Fingerprint) string {
	ja3fp := fmt.Sprintf("%d,%s,%s,%s,%s", myPrint.TLSVersion,
		ja3ByteFormat(myPrint.Ciphersuite), ja3ByteFormat(myPrint.Extensions),
		ja3ByteFormat(myPrint.ECurves), ja3ByteFormat(myPrint.EcPointFmt))
	return ja3fp
}

// ja3ByteFormat reformats a byte array into the decimal-decimal-decimal format used by JA3
func ja3ByteFormat(input []byte) string {
	var output string
	for i := 0; i < len(input); i++ {
		if i == 0 {
			output = fmt.Sprintf("%d", input[0:1])
		} else {
			output = fmt.Sprintf("%s-%d", output, input[i:i+1])
		}
	}
	return output
}

// Ftop is to convert between two similar, but not idential structs
// (fingerprint file, and internal fingerprint storage) which I now want
// to use interchangably, because I'm a tool.
func Ftop(myPrint FingerprintFile) Fingerprint {
	var output Fingerprint

	// Copy and convert the relevent fields
	output.Id = myPrint.ID
	output.Desc = myPrint.Desc
	output.RecordTLSVersion = hexStrToByteArray(myPrint.RecordTLSVersion)
	output.TLSVersion = hexStrToByteArray(myPrint.TLSVersion)
	output.Ciphersuite = hexStrToByteArray(myPrint.Ciphersuite)
	output.Compression = hexStrToByteArray(myPrint.Compression)
	output.Extensions = hexStrToByteArray(myPrint.Extensions)
	output.ECurves = hexStrToByteArray(myPrint.ECurves)
	output.SigAlg = hexStrToByteArray(myPrint.SigAlg)
	output.EcPointFmt = hexStrToByteArray(myPrint.ECPointFmt)
	output.SupportedVersions = hexStrToByteArray(myPrint.SupportedVersions)
	output.Grease = myPrint.Grease

	return output
}

// Add adds a fingerprint to the internal DB
func Add(myPrint Fingerprint, myDB map[uint64]string) {
	myHash := hash(myPrint)
	if _, ok := myDB[myHash]; ok {
		fmt.Printf("Hash Collision: %v %s and %s\n", myHash, myDB[myHash], myPrint.Desc)
	} else {
		myDB[myHash] = myPrint.Desc
		fmt.Printf("New FP Hash %v : %s\n", myHash, myPrint.Desc)
	}
	tempFPCounter++
}

// lookup is used to lookup the name of a fingerprint given the JSON representation
func lookup(myPrint Fingerprint, myDB map[uint64]string) (string, bool, uint64) {
	myHash := hash(myPrint)
	fmt.Printf("Looking up hash: %v\n", myHash)
	if value, ok := myDB[myHash]; ok {
		return value, true, myHash
	}
	return "", false, myHash
}
