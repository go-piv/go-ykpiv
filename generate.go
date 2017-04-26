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
	"fmt"

	"encoding/asn1"
	"math/big"

	"crypto"
	"crypto/rsa"
)

var (
	ykpivInsGenerateAsymetric byte = 0x47
)

func decodeYubikeyRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	data := asn1.RawValue{}
	rest, err := asn1.Unmarshal(der, &data)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("ykpiv: GenerateRSA: der has trailing bytes")
	}

	der = data.Bytes

	n := asn1.RawValue{}
	rest, err = asn1.Unmarshal(der, &n)
	if err != nil {
		return nil, err
	}
	if n.Tag != 1 {
		return nil, fmt.Errorf("ykpiv: GenerateRSA: I'm confused about n: %x", n.Tag)
	}
	e := asn1.RawValue{}
	rest, err = asn1.Unmarshal(rest, &e)
	if err != nil {
		return nil, err
	}
	if e.Tag != 2 {
		return nil, fmt.Errorf("ykpiv: GenerateRSA: I'm confused about e: %x", e.Tag)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("ykpiv: GenerateRSA: bad pubkey der")
	}
	pubN := big.NewInt(0)
	pubN.SetBytes(n.Bytes)

	pubE := big.NewInt(0)
	pubE.SetBytes(e.Bytes)

	pubKey := rsa.PublicKey{
		N: pubN,
		E: int(pubE.Int64()),
	}

	return &pubKey, nil
}

func (y Yubikey) GenerateRSASlot(id SlotId, bits int) (*Slot, error) {
	pubKey, err := y.generateRSA(id, bits)
	if err != nil {
		return nil, err
	}

	return &Slot{yubikey: y, Id: id, PublicKey: pubKey}, nil

}

// This ketamine fueled nightmare
func (y Yubikey) generateRSA(slot SlotId, bits int) (crypto.PublicKey, error) {
	var algorithm byte
	switch bits {
	case 1024:
		algorithm = C.YKPIV_ALGO_RSA1024
	case 2048:
		algorithm = C.YKPIV_ALGO_RSA2048
	default:
		return nil, fmt.Errorf("ykpiv: GenerateRSA: Unknown bit size: %d", bits)
	}

	der, err := y.generateKey(slot, algorithm)
	if err != nil {
		return nil, err
	}

	return decodeYubikeyRSAPublicKey(der)
}

func (y Yubikey) generateKey(slot SlotId, algorithm byte) ([]byte, error) {
	sw, data, err := y.transferData(
		[]byte{0x00, ykpivInsGenerateAsymetric, 0x00, byte(slot.Key)},
		[]byte{
			0xAC, 3,
			C.YKPIV_ALGO_TAG, 1, algorithm,
		},
		1024,
	)
	if err != nil {
		return nil, err
	}

	switch sw {
	case C.SW_SUCCESS:
		// lookin good
	case C.SW_ERR_SECURITY_STATUS:
		return nil, fmt.Errorf("ykpiv: GenerateKey: Security Status Error")
	case C.SW_ERR_AUTH_BLOCKED:
		return nil, fmt.Errorf("ykpiv: GenerateKey: Auth Blocked")
	case C.SW_ERR_INCORRECT_PARAM:
		return nil, fmt.Errorf("ykpiv: GenerateKey: Incorrect Param")
	case C.SW_ERR_INCORRECT_SLOT:
		return nil, fmt.Errorf("ykpiv: GenerateKey: Incorrect Slot")
	default:
	}

	return data, nil
}

// vim: foldmethod=marker
