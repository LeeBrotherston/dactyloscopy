package dactyloscopy

import (
	"fmt"

	"github.com/spaolacci/murmur3"
)

// hash generates the hash of the FP, to be used in the FP lookup tables
func hash(myPrint Fingerprint) uint64 {
	hasher := murmur3.New64()
	// Throw the various values into the hashererererer
	hasher.Write([]byte(myPrint.ciphersuite))
	hasher.Write([]byte(myPrint.compression))
	hasher.Write([]byte(myPrint.ecPointFmt))
	hasher.Write([]byte(myPrint.eCurves))
	hasher.Write([]byte(myPrint.extensions))
	if myPrint.grease == true {
		hasher.Write([]byte("true"))
	} else {
		hasher.Write([]byte("false"))
	}
	hasher.Write([]byte(myPrint.recordTLSVersion))
	hasher.Write([]byte(myPrint.sigAlg))
	hasher.Write([]byte(myPrint.TLSVersion))
	hasher.Write([]byte(myPrint.supportedVersions))
	myHash := hasher.Sum64()
	return myHash
}

// Ftop is to convert between two similar, but not idential structs
// (fingerprint file, and internal fingerprint storage) which I now want
// to use interchangably, because I'm a tool.
func Ftop(myPrint FingerprintFile) Fingerprint {
	var output Fingerprint

	// Copy and convert the relevent fields
	output.id = myPrint.ID
	output.desc = myPrint.Desc
	output.recordTLSVersion = hexStrToByteArray(myPrint.RecordTLSVersion)
	output.TLSVersion = hexStrToByteArray(myPrint.TLSVersion)
	output.ciphersuite = hexStrToByteArray(myPrint.Ciphersuite)
	output.compression = hexStrToByteArray(myPrint.Compression)
	output.extensions = hexStrToByteArray(myPrint.Extensions)
	output.eCurves = hexStrToByteArray(myPrint.ECurves)
	output.sigAlg = hexStrToByteArray(myPrint.SigAlg)
	output.ecPointFmt = hexStrToByteArray(myPrint.ECPointFmt)
	output.supportedVersions = hexStrToByteArray(myPrint.SupportedVersions)
	output.grease = myPrint.Grease

	return output
}

// Add adds a fingerprint to the internal DB
func Add(myPrint Fingerprint, myDB map[uint64]string) {
	myHash := hash(myPrint)
	if _, ok := myDB[myHash]; ok {
		fmt.Printf("Hash Collision: %v %s and %s\n", myHash, myDB[myHash], myPrint.desc)
	} else {
		myDB[myHash] = myPrint.desc
		fmt.Printf("New FP Hash %v : %s\n", myHash, myPrint.desc)
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
