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

package encoding

import (
	"fmt"
)

// I have no idea where this shit comes from, and all of this is based on
// my half-assed 2am read of the yubico-piv-tool source code. In particular
// the Postfix bits don't even pretend to be real.

type Bytes struct {
	Prefix struct {
		Magic byte
	}

	Postfix struct {
		Magic     byte
		MoreMagic byte
		Compress  byte
		LRC       byte
	}

	Data []byte
}

func expandBytes(els ...[]byte) []byte {
	out := []byte{}
	for _, el := range els {
		out = append(out, el...)
	}
	return out
}

// Encode a Bytes object into one of these length encoded and tagged byte
// streams
func (b Bytes) Encode() []byte {
	return expandBytes(
		[]byte{b.Prefix.Magic},
		lengthBytes(int16(len(b.Data))),
		b.Data,
		[]byte{
			b.Postfix.Magic,
			b.Postfix.MoreMagic,
			b.Postfix.Compress,
			b.Postfix.LRC,
			0x00,
		},
	)
}

// Use a dynamic length header to determine the length of the bytes following.
func lengthBytes(length int16) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length < 0xff {
		return []byte{0x81, byte(length)}
	}
	return []byte{
		0x82,
		byte(length>>8) & 0xFF,
		byte(length) & 0xFF,
	}
}

func determineLength(data []byte) (int, int16, error) {
	if data[0] < 0x81 {
		return 1, int16(data[0]), nil
	}
	if data[0]&0x7F == 1 {
		return 2, int16(data[1]), nil
	}
	if data[0]&0x7F == 2 {
		return 3, int16((int16(data[1]) << 8) + int16(data[2])), nil
	}
	return 0, 0, fmt.Errorf("Some jacked up bytes in our header")
}

func Decode(data []byte) (*Bytes, []byte, error) {
	headerLength, dataLength, err := determineLength(data[1:])
	if err != nil {
		return nil, nil, err
	}

	out := Bytes{}

	out.Prefix.Magic = data[0]

	// First, we're going to remove the header from the data we've
	// been given, since we've stored the interesting bytes already.
	data = data[headerLength+1:]

	out.Data = data[:dataLength]

	// Now, let's store the postfix
	postfix := data[dataLength : dataLength+5]

	out.Postfix.Magic = postfix[0]
	out.Postfix.MoreMagic = postfix[1]
	out.Postfix.Compress = postfix[2]
	out.Postfix.LRC = postfix[3]

	rest := data[dataLength+5:]

	return &out, rest, nil
}

// vim: foldmethod=marker
