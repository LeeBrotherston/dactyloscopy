package dactyloscopy

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/cryptobyte"
)

func TestSortNumeric(t *testing.T) {
	var (
		inU32 []uint32
		inU16 []uint16
		inU8  []uint8
	)
	// Create a random assortment of numbers in a slice
	for x := 0; x <= 32; x++ {
		inU32 = append(inU32, uint32(rand.Intn(4294967295)))
	}
	for x := 0; x <= 32; x++ {
		inU16 = append(inU16, uint16(rand.Intn(65535)))
	}
	for x := 0; x <= 32; x++ {
		inU8 = append(inU8, uint8(rand.Intn(255)))
	}

	checkSort(t, inU32)
	checkSort(t, inU16)
	checkSort(t, inU8)
}

func checkSort[T int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32 | uint64 | float32 | float64](t *testing.T, in []T) {
	t.Helper()
	result := sortNumericDesc(in)
	t.Logf("Test Sort Numberic InType=%T OutType=%T In=%+v Out=%+v", in, result, in, result)
	var prev T
	for x, y := range result {
		if x == 0 {
			prev = y
		} else {
			if y > prev {
				t.Fail()
			}
		}
	}

	// Check that the in and out types match
	if reflect.TypeOf(in) != reflect.TypeOf(result) {
		t.Fail()
	}

	// Sort and check they are in the right order
	result = sortNumericAsc(in)
	t.Logf("Test Sort Numberic InType=%T OutType=%T In=%+v Out=%+v", in, result, in, result)
	for x, y := range result {
		if x == 0 {
			prev = y
		} else {
			if y < prev {
				t.Fail()
			}
		}
	}

	// Check that the in and out types match
	if reflect.TypeOf(in) != reflect.TypeOf(result) {
		t.Fail()
	}
}

func TestReadXLengthYVal(t *testing.T) {
	var (
		out8  []uint8
		out16 []uint16
	)
	in := cryptobyte.String([]byte{0x03, 0x05, 0x01, 0x02})
	err := readXLengthYVal(&in, &out8, 1)
	if err != nil {
		t.Errorf("readXLengthYVal() error = %v", err)
	}
	assert.Equal(t, out8, []uint8{0x05, 0x01, 0x02}, "readXLengthYVal() mismatch")

	out8 = []uint8{}
	in = cryptobyte.String([]byte{0x00, 0x03, 0x05, 0x01, 0x02})
	err = readXLengthYVal(&in, &out8, 2)
	if err != nil {
		t.Errorf("readXLengthYVal() error = %v", err)
	}
	assert.Equal(t, out8, []uint8{0x05, 0x01, 0x02}, "readXLengthYVal() mismatch")

	in = cryptobyte.String([]byte{0x00, 0x04, 0x05, 0x01, 0x02, 0x07})
	err = readXLengthYVal(&in, &out16, 2)
	if err != nil {
		t.Errorf("readXLengthYVal() error = %v", err)
	}
	assert.Equal(t, out16, []uint16{0x0501, 0x0207}, "readXLengthYVal() mismatch")
}
