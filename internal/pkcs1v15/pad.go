package pkcs1v15

import (
	"fmt"
)

// PKCS#1 1.5 defines a method to pad data passed into a signing operation
// which is (basically) to set some bits at the lower indexes, then a bunch of
// 0xFF, finally, a 0x00, then the data until the end of the block.

// Pad a message to padLen bytes according to PKCS#1 v1.5 rules
func Pad(message []byte, padLen int) []byte {
	padding := make([]byte, (padLen - 3 - len(message)))
	for i := 0; i < len(padding); i++ {
		padding[i] = 0xFF
	}
	return expandBytes([]byte{0x00, 0x01}, padding, []byte{0x00}, message)
}

// Unpad a message according to PKCS#1 v1.5 rules
func Unpad(message []byte) ([]byte, error) {
	for i := 2; i < len(message); i++ {
		if message[i] == 0x00 {
			return message[i+1:], nil
		}
	}
	return nil, fmt.Errorf("Input does not appear to be in PKCS#1 v 1.5 padded format")
}

// Take some byte arrays, and return the concatenation of all of those byte
// arrays. It's basically like append, but for byte arrays, not bytes.
func expandBytes(els ...[]byte) []byte {
	out := []byte{}
	for _, el := range els {
		out = append(out, el...)
	}
	return out
}

// func Unpad(
