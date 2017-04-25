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

package ykpiv

/*
#cgo LDFLAGS: -lykpiv
#cgo CFLAGS: -I/usr/include/ykpiv/
#include <ykpiv.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto"
	"encoding/asn1"

	"golang.org/x/crypto/pbkdf2"
)

var (
	pivmanObjData = 0x5FFF00

	/* pivman's source defines this as 0x80, but since we're using an actual
	 * der decoder, we'll see the tag value, which would just be 1 */
	pivmanTagFlags1    = 0x01
	pivmanTagSalt      = 0x02
	pivmanTagTimestamp = 0x03

	pivmanTagFlags1PUKBlocked = 0x01
)

// Get the salt off the Yubikey PIV token, which is stored in a DER encoded
// array of arrays. This salt is a couple of bytes of calming entropy.
func (y Yubikey) getSalt() ([]byte, error) {
	attributes, err := y.getPIVMANAttributes()
	if err != nil {
		return nil, err
	}
	return attributes[pivmanTagSalt], nil
}

// Compute the PIVMAN Management Key using 10000 rounds of PBKDF2 SHA1
// utilizing the salt off the Yubikey to derive the 3DES management key.
func (y Yubikey) deriveManagementKey() ([]byte, error) {
	// Description of the Management key derivation can be found on the
	// Yubikey website:
	// https://developers.yubico.com/yubikey-piv-manager/PIN_and_Management_Key.html
	//
	// Technical description of Key derivation from PIN
	//
	// When choosing to use a Management Key derived from the PIN, the following takes place:
	//
	// A random 8-byte SALT value is generated and stored on the YubiKey.
	//
	// The derived Management Key is calculated as PBKDF2(PIN, SALT, 24, 10000).
	//
	// The PBKDF2 function (described in RFC 2898) is run using the PIN
	// (encoded using UTF-8) as the password, for 10000 rounds, to produce a 24
	// byte key, which is used as the management key. Whenever the user changes
	// the PIN this process is repeated, using a new SALT and the new PIN.
	pin, err := y.options.GetPIN()
	if err != nil {
		return nil, err
	}

	salt, err := y.getSalt()
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key([]byte(pin), salt, 10000, 24, crypto.SHA1.New), nil
}

// Return a mapping of pivmanTags -> byte arrays. The exact semantics
// of this byte array is defined entirely by the tag, and should be treated
// as semantically opaque to the user, unless specific parsing code is in place.
func (y Yubikey) getPIVMANAttributes() (map[int][]byte, error) {
	attributes := map[int][]byte{}

	bytes, err := y.getObject(pivmanObjData)
	if err != nil {
		return nil, err
	}

	/* What we've got here is an DER encoded byte array, which holds
	 * DER encoded byte arrays. */
	rawData := asn1.RawValue{}
	if _, err := asn1.Unmarshal(bytes, &rawData); err != nil {
		return nil, err
	}

	// So, now that we have the byte array, let's break it apart.
	bytes = rawData.Bytes
	for {
		/* When we asn1.Unmarshal, the "rest", is just the next chunk
		 * of the byte array, basically. So, let's continue until we've
		 * hit the end of the array */
		rawData := asn1.RawValue{}
		rest, err := asn1.Unmarshal(bytes, &rawData)
		if err != nil {
			return nil, err
		}
		attributes[rawData.Tag] = rawData.Bytes
		if len(rest) == 0 {
			break
		}
		bytes = rest
	}
	return attributes, nil
}

// vim: foldmethod=marker
