package dactyloscopy

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

func skip16(data cryptobyte.String) error {
	var skipsize uint16 = 0
	if !data.ReadUint16(&skipsize) {
		return fmt.Errorf("could not read skip size")
	}

	if skipsize > 0 {
		if !data.Skip(int(skipsize)) {
			return fmt.Errorf("could not skip")
		}
	}
	return nil
}

func read16Length16Pair(dataBlock cryptobyte.String, output *[]uint16) error {
	var (
		valueList   cryptobyte.String
		singleValue uint16
	)
	if !dataBlock.ReadUint16LengthPrefixed(&valueList) {
		return fmt.Errorf("could not read list of values")
	}

	for !valueList.Empty() {
		valueList.ReadUint16(&singleValue)
		*output = append(*output, singleValue)
	}
	return nil
}

func read16Length8Pair(dataBlock cryptobyte.String, output *[]uint8) error {
	var (
		valueList   cryptobyte.String
		singleValue uint8
	)
	if !dataBlock.ReadUint16LengthPrefixed(&valueList) {
		return fmt.Errorf("could not read list of values")
	}

	for !valueList.Empty() {
		valueList.ReadUint8(&singleValue)
		*output = append(*output, singleValue)
	}
	return nil
}
