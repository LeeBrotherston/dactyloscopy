package dactyloscopy

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

func skip16(data cryptobyte.String) error {
	var skipsize uint16 = 0
	if !data.ReadUint16(&skipsize) {
		return fmt.Errorf("could not read skip size, data=[%X]", data)
	}

	if skipsize > 0 {
		if !data.Skip(int(skipsize)) {
			return fmt.Errorf("could not skip")
		}
	}
	return nil
}

func read16Length16Pair(dataBlock *cryptobyte.String, output *[]uint16) error {
	var outputInt []uint64
	err := readXLengthYVal(dataBlock, &outputInt, 2, 2)
	if err != nil {
		return err
	}
	for _, y := range outputInt {
		*output = append(*output, uint16(y))
	}
	return nil
}

func read16Length8Pair(dataBlock *cryptobyte.String, output *[]uint8) error {
	var outputInt []uint64
	err := readXLengthYVal(dataBlock, &outputInt, 2, 1)
	if err != nil {
		return err
	}
	for _, y := range outputInt {
		*output = append(*output, uint8(y))
	}
	return nil
}

func read8Length16Pair(dataBlock *cryptobyte.String, output *[]uint16) error {
	var outputInt []uint64
	err := readXLengthYVal(dataBlock, &outputInt, 1, 2)
	if err != nil {
		return err
	}
	for _, y := range outputInt {
		*output = append(*output, uint16(y))
	}
	return nil
}

func readXLengthYVal(dataBlock *cryptobyte.String, output *[]uint64, lengthSize int, valueSize int) error {
	var (
		lengthBytes []byte
		debugStr    string
	)
	debugStr = fmt.Sprintf("data=[%X]", *dataBlock)
	if dataBlock.Empty() {
		return fmt.Errorf("dataBlock is empty in readXLengthYVal")
	}
	if !dataBlock.ReadBytes(&lengthBytes, lengthSize) {
		return fmt.Errorf("could not read length values using readXLengthYVal")
	}
	debugStr = fmt.Sprintf("%s length_bytes=[%d] using size=[%d]", debugStr, lengthBytes, lengthSize)
	if lengthSize == 0 {
		return fmt.Errorf("length is zero in readXLengthYVal, lengthSize=[%d], data=[%X]", lengthSize, *dataBlock)
	}

	// calculate length from lengthBytes
	length := 0
	for counter, lengthByte := range lengthBytes {
		length = int(length)<<(counter*8) | int(lengthByte)
	}

	for !dataBlock.Empty() {
		switch valueSize {
		case 1:
			var singleValue uint8
			if !dataBlock.ReadUint8(&singleValue) {
				return fmt.Errorf("could not read uint8 value in readXLengthYVal, debug %s", debugStr)
			}
			*output = append(*output, uint64(singleValue))
		case 2:
			var singleValue uint16
			if !dataBlock.ReadUint16(&singleValue) {
				return fmt.Errorf("could not read uint16 value in readXLengthYVal, debug %s", debugStr)
			}
			*output = append(*output, uint64(singleValue))
		case 4:
			var singleValue uint32
			if !dataBlock.ReadUint32(&singleValue) {
				return fmt.Errorf("could not read uint32 value in readXLengthYVal, debug %s", debugStr)
			}
			*output = append(*output, uint64(singleValue))
		case 8:
			var singleValue uint64
			if !dataBlock.ReadUint64(&singleValue) {
				return fmt.Errorf("could not read uint64 value in readXLengthYVal, debug %s", debugStr)
			}
			*output = append(*output, singleValue)
		default:
			return fmt.Errorf("invalid value size %d in readXLengthYVal, debug %s", valueSize, debugStr)
		}
	}

	return nil
}

func readXLengthToCryptoByte(dataBlock *cryptobyte.String, out *cryptobyte.String, lengthSize int) error {
	var (
		lengthBytes []byte
		debugStr    string
	)
	debugStr = fmt.Sprintf("data=[%X]", *dataBlock)
	if dataBlock.Empty() {
		return fmt.Errorf("dataBlock is empty in readXLengthToCryptoByte")
	}
	if !dataBlock.ReadBytes(&lengthBytes, lengthSize) {
		return fmt.Errorf("could not read length values using readXLengthToCryptoByte")
	}
	debugStr = fmt.Sprintf("%s length_bytes=[%d] using size=[%d]", debugStr, lengthBytes, lengthSize)
	if lengthSize == 0 {
		return fmt.Errorf("length is zero in readXLengthToCryptoByte, lengthSize=[%d], data=[%X]", lengthSize, *dataBlock)
	}

	// calculate length from lengthBytes
	length := 0
	for counter, lengthByte := range lengthBytes {
		length = int(length)<<(counter*8) | int(lengthByte)
	}

	var byteOut []byte
	if !dataBlock.ReadBytes(&byteOut, length) {
		return fmt.Errorf("could not readbytes in readXLengthYValToCryptoByte, lengthSize=[%d], data=[%X]", lengthSize, *dataBlock)
	}

	moo := cryptobyte.String(byteOut)
	*out = moo

	/*

		for !dataBlock.Empty() {
			switch valueSize {
			case 1:
				var singleValue uint8
				if !dataBlock.ReadUint8(&singleValue) {
					return fmt.Errorf("could not read uint8 value in readXLengthYVal, debug %s", debugStr)
				}
				*output = append(*output, uint64(singleValue))
			case 2:
				var singleValue uint16
				if !dataBlock.ReadUint16(&singleValue) {
					return fmt.Errorf("could not read uint16 value in readXLengthYVal, debug %s", debugStr)
				}
				*output = append(*output, uint64(singleValue))
			case 4:
				var singleValue uint32
				if !dataBlock.ReadUint32(&singleValue) {
					return fmt.Errorf("could not read uint32 value in readXLengthYVal, debug %s", debugStr)
				}
				*output = append(*output, uint64(singleValue))
			case 8:
				var singleValue uint64
				if !dataBlock.ReadUint64(&singleValue) {
					return fmt.Errorf("could not read uint64 value in readXLengthYVal, debug %s", debugStr)
				}
				*output = append(*output, singleValue)
			default:
				return fmt.Errorf("invalid value size %d in readXLengthYVal, debug %s", valueSize, debugStr)
			}
		}
	*/

	return nil
}

// sliceToDash16 converts a slice of number values and make a dash delimited
// string representation.. Used for making printable fingerprints.
func sliceToDash16(input []uint16) string {
	var outSlice []string
	for _, i := range input {
		outSlice = append(outSlice, fmt.Sprintf("%d", i))
	}
	return strings.Join(outSlice, "-")
}

// sliceToDash8 converts a slice of number values and make a dash delimited
// string representation.. Used for making printable fingerprints.
func sliceToDash8(input []uint8) string {
	var outSlice []string
	for _, i := range input {
		outSlice = append(outSlice, fmt.Sprintf("%d", i))
	}
	return strings.Join(outSlice, "-")
}

// sortNumeric takes a slice of numeric values, and returns a sorted slice of
// the same type (e.g. []uint8 => sorted []uint8).  Using sort.Slice normally
// results in the source slice being reordered, but sometimes we don't want that
func sortNumericDesc[T int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32 | uint64 | float32 | float64](in []T) []T {
	return sortNumeric(in, true)
}

func sortNumericAsc[T int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32 | uint64 | float32 | float64](in []T) []T {
	return sortNumeric(in, false)
}

func sortNumeric[T int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32 | uint64 | float32 | float64](in []T, ascending bool) []T {
	sortableSlice := make([]T, len(in))
	copy(sortableSlice, in)
	sort.Slice(sortableSlice, func(i, j int) bool {
		if ascending {
			return sortableSlice[i] > sortableSlice[j]
		} else {
			return sortableSlice[i] < sortableSlice[j]
		}
	})
	return sortableSlice
}
