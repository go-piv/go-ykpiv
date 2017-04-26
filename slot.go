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
	"unsafe"

	"encoding/asn1"

	"crypto"
	"crypto/rsa"
	"crypto/x509"

	"pault.ag/go/ykpiv/internal/bytearray"
)

// SlotId encapsulates the Identifiers required to preform key operations
// on the Yubikey. The identifier most people would know (if this is a thing
// that people do who don't write PIV aware applications) would be the `Key`
// Id, something like 0x9A.
type SlotId struct {
	Certificate int32
	Key         int32
}

// Return a human readable string mostly useful for debugging which Slot you
// might have your hands on. Since most people (for some value of "most")
// would want the Key, this only includes that.
func (s SlotId) String() string {
	return fmt.Sprintf("Slot key=%x", s.Key)
}

// More information regarding the basic PIV slots can be founnd at the
// FICAM piv-gude: https://piv.idmanagement.gov/elements/
var (
	// PIV Authentication, which is a certificate and key pair and can be used
	// to verify that the PIV credential was issued by an authorized entity,
	// has not expired, has not been revoked, and holder of the credential
	// (YOU) is the same individual it was issued to.
	Authentication SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_AUTHENTICATION,
		Key:         C.YKPIV_KEY_AUTHENTICATION,
	}

	// Digital Signature, which is a certificate and key pair allows the YOU to
	// digitally sign a document or email, providing both integrity and
	// non-repudiation.
	Signature SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_SIGNATURE,
		Key:         C.YKPIV_KEY_SIGNATURE,
	}

	// Card Authentication, which is a certificate and key pair that can be
	// used to verify that the PIV credential was issued by an authorized
	// entity, has not expired, and has not been revoked.
	CardAuthentication SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_CARD_AUTH,
		Key:         C.YKPIV_KEY_CARDAUTH,
	}

	KeyManagement SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_KEY_MANAGEMENT,
		Key:         C.YKPIV_KEY_KEYMGM,
	}
)

// Slot abstracts a public key, private key, and x509 Certificate stored
// on the PIV device.
//
// Internally, this keeps track of the Yubikey this came from, the underlying
// object identifiers for the Certificate and Key we care about, as well as
// other bits and bobs of state.
type Slot struct {
	yubikey     Yubikey
	Id          SlotId
	PublicKey   crypto.PublicKey
	Certificate *x509.Certificate
}

// Get the PIV Authentication Slot off the Yubikey. This is identical to
// invoking `yubikey.Slot(ykpiv.Authentication)`.
func (y Yubikey) Authentication() (*Slot, error) {
	return y.Slot(Authentication)
}

// Get the Digital Signature Slot off the Yubikey. This is identical to
// invoking `yubikey.Slot(ykpiv.Signature)`
func (y Yubikey) Signature() (*Slot, error) {
	return y.Slot(Signature)
}

// Get the PIV Card Authentication Slot off the Yubikey. This is identical to
// invoking `yubikey.Slot(ykpiv.CardAuthentication)`
func (y Yubikey) CardAuthentication() (*Slot, error) {
	return y.Slot(CardAuthentication)
}

// Get the PIV Key Management Slot off the Yubikey. This is identical to
// invoking `yubikey.Slot(ykpiv.KeyManagement)`
func (y Yubikey) KeyManagement() (*Slot, error) {
	return y.Slot(KeyManagement)
}

// Get a Slot off of the Yubikey by the SlotId.
//
// This will trigger an attempt to get (and parse) the x509 Certificate
// for this slot. Only slots with an x509 Certificate can be used.
func (y Yubikey) Slot(id SlotId) (*Slot, error) {
	/* Right, let's see what we can do here */
	slot := Slot{yubikey: y, Id: id}

	certificate, err := slot.GetCertificate()
	if err != nil {
		return nil, err
	}

	slot.Certificate = certificate
	slot.PublicKey = certificate.PublicKey

	return &slot, nil
}

// Return the crypto.PublicKey that we know corresponds to the Certificate
// we have on hand.
func (s Slot) Public() crypto.PublicKey {
	return s.PublicKey
}

// Get the Yubikey C.YKPIV_ALGO_* uchar for the key material backing the
// slot.
func (y Slot) getAlgorithm() (C.uchar, error) {
	pubKey := y.PublicKey

	switch pubKey.(type) {
	case *rsa.PublicKey:
		rsaPub := pubKey.(*rsa.PublicKey)
		switch rsaPub.N.BitLen() {
		case 1024:
			return C.YKPIV_ALGO_RSA1024, nil
		case 2048:
			return C.YKPIV_ALGO_RSA2048, nil
		default:
			return C.uchar(0), fmt.Errorf("ykpiv: getAlgorithm: Unknown RSA Modulus size")
		}
	default:
		return C.uchar(0), fmt.Errorf("ykpiv: getAlgorithm: Unknown public key algorithm")
	}
}

// Get the x509.Certificate stored in the PIV Slot off the chip
func (y Slot) GetCertificate() (*x509.Certificate, error) {
	bytes, err := y.yubikey.getObject(int(y.Id.Certificate))
	if err != nil {
		return nil, err
	}

	objects, err := bytearray.Decode(bytes)
	if err != nil {
		return nil, err
	}

	if len(objects) != 3 {
		return nil, fmt.Errorf("ykpiv: GetCertificate: We expected two der byte arrays from the key")
	}

	// If this is throwing sequence truncated and/or trailing byte errors
	// the first thing to double check is the byte mangling above, and
	// if the comment above applies to this.
	return x509.ParseCertificate(objects[0].Bytes)
}

// Write the x509 Certificate to the Yubikey.
func (y *Slot) Update(cert x509.Certificate) error {
	digitalTerroristPoison, err := bytearray.Encode([]asn1.RawValue{
		asn1.RawValue{Tag: 0x10, IsCompound: true, Class: 0x01, Bytes: cert.Raw},
		asn1.RawValue{Tag: 0x11, IsCompound: true, Class: 0x01, Bytes: []byte{0x00}},
		asn1.RawValue{Tag: 0x1E, IsCompound: true, Class: 0x03, Bytes: []byte{}},
	})
	if err != nil {
		return err
	}

	cDigitalTerroristPoison := (*C.uchar)(C.CBytes(digitalTerroristPoison))
	cDigitalTerroristPoisonLen := C.size_t(len(digitalTerroristPoison))
	defer C.free(unsafe.Pointer(cDigitalTerroristPoison))

	if err := getError(C.ykpiv_save_object(
		y.yubikey.state,
		C.int(y.Id.Certificate),
		cDigitalTerroristPoison, cDigitalTerroristPoisonLen,
	), "save_object"); err != nil {
		return err
	}

	y.Certificate = &cert
	return nil
}

// vim: foldmethod=marker
