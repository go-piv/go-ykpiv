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

package bytearray

import (
	"encoding/asn1"
)

// Decode will unpack a byte array of DER encoded byte arrays into
// asn1.RawValue structs.
func Decode(bytes []byte) ([]asn1.RawValue, error) {
	ret := []asn1.RawValue{}
	for {
		rawData := asn1.RawValue{}
		rest, err := asn1.Unmarshal(bytes, &rawData)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rawData)
		if len(rest) == 0 {
			break
		}
		bytes = rest
	}
	return ret, nil
}

// This will DER unpack a byte array, and Decode the nested Byte array
// that sits underneath it.
func DERDecode(bytes []byte) ([]asn1.RawValue, error) {
	rawData := asn1.RawValue{}
	if _, err := asn1.Unmarshal(bytes, &rawData); err != nil {
		return nil, err
	}
	return Decode(rawData.Bytes)

}

// Take a list of asn1.RawValue structs, Marshal them, and push the combined
// array into a byte array to drop out.
func Encode(values []asn1.RawValue) ([]byte, error) {
	ret := []byte{}
	for _, value := range values {
		bytes, err := asn1.Marshal(value)
		if err != nil {
			return nil, err
		}
		ret = append(ret, bytes...)
	}
	return ret, nil
}

// vim: foldmethod=marker
