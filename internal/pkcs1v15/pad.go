// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2017
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

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
		if message[i] != 0xFF {
			return nil, fmt.Errorf("ykpiv: pkcs1v15: Invalid padding byte")
		}
	}
	return nil, fmt.Errorf("ykpiv: pkcs1v15: Input does not appear to be in PKCS#1 v 1.5 padded format")
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

// vim: foldmethod=marker
