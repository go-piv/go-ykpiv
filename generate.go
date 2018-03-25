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
#cgo darwin LDFLAGS: -L /usr/local/lib -lykpiv
#cgo darwin CFLAGS: -I/usr/local/include/ykpiv/
#cgo linux LDFLAGS: -lykpiv
#cgo linux CFLAGS: -I/usr/include/ykpiv/
#include <ykpiv.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"

	"math/big"

	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"pault.ag/go/ykpiv/internal/bytearray"
)

type TouchPolicy byte

const (
	TouchPolicyNull   TouchPolicy = 0
	TouchPolicyNever              = TouchPolicy(C.YKPIV_TOUCHPOLICY_NEVER)
	TouchPolicyAlways             = TouchPolicy(C.YKPIV_TOUCHPOLICY_ALWAYS)
	TouchPolicyCached             = TouchPolicy(C.YKPIV_TOUCHPOLICY_CACHED)
)

type PinPolicy byte

const (
	PinPolicyNull   PinPolicy = 0
	PinPolicyNever            = PinPolicy(C.YKPIV_PINPOLICY_NEVER)
	PinPolicyOnce             = PinPolicy(C.YKPIV_PINPOLICY_ONCE)
	PinPolicyAlways           = PinPolicy(C.YKPIV_PINPOLICY_ALWAYS)
)

// Decode a DER encoded list of byte arrays into an rsa.PublicKey.
func decodeYubikeyRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	byteArray, err := bytearray.DERDecode(der)
	if err != nil {
		return nil, err
	}

	if len(byteArray) != 2 {
		return nil, fmt.Errorf("ykpiv: decodeYubikeyRSAPublicKey: Byte Array isn't length 2")
	}

	n := byteArray[0]
	if n.Tag != 1 {
		return nil, fmt.Errorf("ykpiv: decodeYubikeyRSAPublicKey: I'm confused about n: %x", n.Tag)
	}
	pubN := big.NewInt(0)
	pubN.SetBytes(n.Bytes)

	e := byteArray[1]
	if e.Tag != 2 {
		return nil, fmt.Errorf("ykpiv: decodeYubikeyRSAPublicKey: I'm confused about e: %x", e.Tag)
	}
	pubE := big.NewInt(0)
	pubE.SetBytes(e.Bytes)

	pubKey := rsa.PublicKey{
		N: pubN,
		E: int(pubE.Int64()),
	}

	return &pubKey, nil
}

func decodeYubikeyECPublicKey(curve elliptic.Curve, der []byte) (*ecdsa.PublicKey, error) {
	byteArray, err := bytearray.DERDecode(der)
	if err != nil {
		return nil, err
	}

	if len(byteArray) != 1 {
		return nil, fmt.Errorf("ykpiv: decodeYubikeyECPublicKey: Byte Array isn't length 1")
	}

	publicPointSpec := byteArray[0].Bytes
	if publicPointSpec[0] != 0x04 {
		return nil, fmt.Errorf("ykpiv: decodeYubikeyECPublicKey: EC public point byte != 4: %d", publicPointSpec[0])
	}

	pointLen := (curve.Params().BitSize + 7) / 8
	if len(publicPointSpec) != 2*pointLen+1 {
		return nil, fmt.Errorf("ykpiv: decodeYubikeyECPublicKey: EC public point bytes wrong length; %d", len(publicPointSpec))
	}

	x := new(big.Int)
	x.SetBytes(publicPointSpec[1 : 1+pointLen])
	y := new(big.Int)
	y.SetBytes(publicPointSpec[1+pointLen : 1+2*pointLen])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// Generate an RSA Keypair in slot `id` (using a modulus size of `bits`),
// and construct a Certificate-less Slot. This Slot can not be recovered
// later, so it should be used to sign a CSR or Self-Signed Certificate
// before we lose the key material.
func (y Yubikey) GenerateRSA(id SlotId, bits int) (*Slot, error) {
	return y.GenerateRSAWithPolicies(id, bits, PinPolicyNull, TouchPolicyNull)
}

// The same as GenerateRSAWithPolicies, but with additional parameters to
// specify the pin policy and touch policy to be assigned to the generated
// key.
func (y Yubikey) GenerateRSAWithPolicies(id SlotId, bits int, pinPolicy PinPolicy, touchPolicy TouchPolicy) (*Slot, error) {
	pubKey, err := y.generateRSAKey(id, bits, pinPolicy, touchPolicy)
	if err != nil {
		return nil, err
	}

	return &Slot{yubikey: y, Id: id, PublicKey: pubKey}, nil

}

// Generate an RSA public key on the Yubikey, parse the output and return
// a crypto.PublicKey. This will create the key in slot `slot`, with a
// modulus size of `bits`.
func (y Yubikey) generateRSAKey(slot SlotId, bits int, pinPolicy PinPolicy, touchPolicy TouchPolicy) (crypto.PublicKey, error) {
	var algorithm byte
	switch bits {
	case 1024:
		algorithm = C.YKPIV_ALGO_RSA1024
	case 2048:
		algorithm = C.YKPIV_ALGO_RSA2048
	default:
		return nil, fmt.Errorf("ykpiv: GenerateRSA: Unknown bit size: %d", bits)
	}

	der, err := y.generateKey(slot, algorithm, pinPolicy, touchPolicy)
	if err != nil {
		return nil, err
	}

	return decodeYubikeyRSAPublicKey(der)
}

func (y Yubikey) GenerateEC(slot SlotId, bits int) (*Slot, error) {
	return y.GenerateECWithPolicies(slot, bits, PinPolicyNull, TouchPolicyNull)
}

func (y Yubikey) GenerateECWithPolicies(slot SlotId, bits int, pinPolicy PinPolicy, touchPolicy TouchPolicy) (*Slot, error) {
	pubKey, err := y.generateECKey(slot, bits, pinPolicy, touchPolicy)
	if err != nil {
		return nil, err
	}

	return &Slot{yubikey: y, Id: slot, PublicKey: pubKey}, nil
}

func (y Yubikey) generateECKey(slot SlotId, bits int, pinPolicy PinPolicy, touchPolicy TouchPolicy) (crypto.PublicKey, error) {
	var curve elliptic.Curve
	var algorithm byte
	switch bits {
	case 256:
		curve = elliptic.P256()
		algorithm = C.YKPIV_ALGO_ECCP256
	case 384:
		curve = elliptic.P384()
		algorithm = C.YKPIV_ALGO_ECCP384
	default:
		return nil, fmt.Errorf("ykpiv: generateECKey: Unknown bit size: %d", bits)
	}

	der, err := y.generateKey(slot, algorithm, pinPolicy, touchPolicy)
	if err != nil {
		return nil, err
	}

	pubKey, err := decodeYubikeyECPublicKey(curve, der)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// This is a low-level binding into the underlying instruction to actually
// generate a new asymetric key on the Yubikey. This will create a key of
// type `algorithm` (something like C.YKPIV_ALGO_RSA2048) in slot `slot`.
//
// This will return the raw bytes from the actual Yubikey itself back to
// the caller to appropriately parse the output. In the case of RSA keys,
// this is a DER encoded series of DER encoded byte arrays for N and E.
func (y Yubikey) generateKey(slot SlotId, algorithm byte, pinPolicy PinPolicy, touchPolicy TouchPolicy) ([]byte, error) {

	inData := []byte{C.YKPIV_ALGO_TAG, 1, algorithm}
	if pinPolicy != PinPolicyNull {
		inData = append(inData, C.YKPIV_PINPOLICY_TAG, 1, byte(pinPolicy))
	}
	if touchPolicy != TouchPolicyNull {
		inData = append(inData, C.YKPIV_TOUCHPOLICY_TAG, 1, byte(touchPolicy))
	}

	// Prepend with 0xAC and length of the inData
	inData = append([]byte{0xAC, byte(len(inData))}, inData...)

	sw, data, err := y.transferData(
		[]byte{0x00, byte(C.YKPIV_INS_GENERATE_ASYMMETRIC), 0x00, byte(slot.Key)},
		inData,
		1024,
	)
	if err != nil {
		return nil, err
	}

	err = getSWError(sw, "transfer_data")
	if err != nil {
		return nil, err
	}

	return data, nil
}

// vim: foldmethod=marker
