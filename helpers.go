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

func readXLengthYVal[Y uint8 | uint16 | uint32 | uint64](dataBlock *cryptobyte.String, output *[]Y, lengthSize int) error {
	var (
		singleValue Y
		lengthBytes []byte
	)
	if dataBlock.Empty() {
		return fmt.Errorf("dataBlock is empty in readXLengthYVal")
	}
	// Will skip ahead over the length section
	if !dataBlock.ReadBytes(&lengthBytes, lengthSize) {
		return fmt.Errorf("could not read length values using readXLengthYVal")
	}
	if lengthSize == 0 {
		return fmt.Errorf("length is zero in readXLengthYVal, lengthSize=[%d], data=[%X]", lengthSize, *dataBlock)
	}

	// calculate length from lengthBytes
	length := 0
	for counter, lengthByte := range lengthBytes {
		length = int(length)<<(counter*8) | int(lengthByte)
	}

	for !dataBlock.Empty() {
		// This silliness is to allow us to switch on a generic
		switch v := any(singleValue).(type) {
		case uint8:
			if !dataBlock.ReadUint8(&v) {
				return fmt.Errorf("could not read next block, length misalignment")
			}
			*output = append(*output, Y(v))
		case uint16:
			if !dataBlock.ReadUint16(&v) {
				return fmt.Errorf("could not read next block, length misalignment")
			}
			*output = append(*output, Y(v))
		case uint32:
			if !dataBlock.ReadUint32(&v) {
				return fmt.Errorf("could not read next block, length misalignment")
			}
			*output = append(*output, Y(v))
		case uint64:
			if !dataBlock.ReadUint64(&v) {
				return fmt.Errorf("could not read next block, length misalignment")
			}
			*output = append(*output, Y(v))
		default:
			return fmt.Errorf("could not read next block, unexpected type")
		}
	}
	return nil
}

func readXLengthYPair[Y uint8 | uint16 | uint32 | uint64](dataBlock *cryptobyte.String, output *[]Y) error {
	var outputInt []Y
	err := readXLengthYVal(dataBlock, &outputInt, 2)
	if err != nil {
		return err
	}
	*output = append(*output, outputInt...)
	return nil
}

func read16Length16Pair(dataBlock *cryptobyte.String, output *[]uint16) error {
	return readXLengthYPair(dataBlock, output)
}

func read16Length8Pair(dataBlock *cryptobyte.String, output *[]uint8) error {
	return readXLengthYPair(dataBlock, output)
}

func read8Length16Pair(dataBlock *cryptobyte.String, output *[]uint16) error {
	return readXLengthYPair(dataBlock, output)
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
