package tlsfingerprinting

import (
	"fmt"

	"github.com/spaolacci/murmur3"
)

// hashPrint generates the hash of the FP, to be used in the FP lookup tables
func hashPrint(myPrint Fingerprint) uint64 {
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
	myHash := hasher.Sum64()
	return myHash
}

// fpFiletoFP is to convert between two similar, but not idential structs which I now want
// to use them interchangably, because I'm a tool.
func fpFiletoFP(myPrint fingerprintFile) Fingerprint {
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
	output.grease = myPrint.Grease

	return output
}

// And now the hashed versions, whereby we do not actually need to store the FPs at all.
func addPrintNew(myPrint Fingerprint, myDB map[uint64]string) {
	myHash := hashPrint(myPrint)
	if _, ok := myDB[myHash]; ok {
		fmt.Printf("Hash Collision: %v %s and %s\n", myHash, myDB[myHash], myPrint.desc)
	} else {
		myDB[myHash] = myPrint.desc
		fmt.Printf("New FP Hash %v : %s\n", myHash, myPrint.desc)
	}
	tempFPCounter++
}

// lookupFingerprint is used to lookup the name of a fingerprint given the JSON representation
func lookupFingerprint(myPrint Fingerprint, myDB map[uint64]string) (string, bool, uint64) {
	myHash := hashPrint(myPrint)
	fmt.Printf("Looking up hash: %v\n", myHash)
	if value, ok := myDB[myHash]; ok {
		return value, true, myHash
	}
	return "", false, myHash
}
