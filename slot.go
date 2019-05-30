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
#cgo linux CFLAGS: -I/usr/local/include/ykpiv/ -I/usr/include/ykpiv/
#include <ykpiv.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"

	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
)

// SlotId encapsulates the Identifiers required to preform key operations
// on the Yubikey. The identifier most people would know (if this is a thing
// that people do who don't write PIV aware applications) would be the `Key`
// Id, something like 0x9A.
type SlotId struct {
	Certificate int32
	Key         int32
	Name        string
}

// Return a human readable string mostly useful for debugging which Slot you
// might have your hands on. Since most people (for some value of "most")
// would want the Key, this only includes that.
func (s SlotId) String() string {
	return fmt.Sprintf("%s (%x)", s.Name, s.Key)
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
		Name:        "Authentication",
	}

	// Digital Signature, which is a certificate and key pair allows the YOU to
	// digitally sign a document or email, providing both integrity and
	// non-repudiation.
	Signature SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_SIGNATURE,
		Key:         C.YKPIV_KEY_SIGNATURE,
		Name:        "Digital Signature",
	}

	// Card Authentication, which is a certificate and key pair that can be
	// used to verify that the PIV credential was issued by an authorized
	// entity, has not expired, and has not been revoked.
	CardAuthentication SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_CARD_AUTH,
		Key:         C.YKPIV_KEY_CARDAUTH,
		Name:        "Card Authentication",
	}

	KeyManagement SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_KEY_MANAGEMENT,
		Key:         C.YKPIV_KEY_KEYMGM,
		Name:        "Key Management",
	}

	// Attestation, which contains a certificate issued by the Yubico CA
	// and can be used to attest keys generated in the other slots.
	// Requires YubiKey 4.3 or later.
	// NB: if this key or cert is overwritten it cannot be brought back!
	Attestation SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_ATTESTATION,
		Key:         C.YKPIV_KEY_ATTESTATION,
		Name:        "Attestation",
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
	case *ecdsa.PublicKey:
		ecPub := pubKey.(*ecdsa.PublicKey)
		switch ecPub.Params().BitSize {
		case 256:
			return C.YKPIV_ALGO_ECCP256, nil
		case 384:
			return C.YKPIV_ALGO_ECCP384, nil
		default:
			return C.uchar(0), fmt.Errorf("ykpiv: getAlgorithm: Unknown ECDSA curive size")
		}
	default:
		return C.uchar(0), fmt.Errorf("ykpiv: getAlgorithm: Unknown public key algorithm")
	}
}

// Attest the key in this slot and get the attestation certificate
func (y Slot) Attest() (*x509.Certificate, error) {
	return y.yubikey.Attest(y.Id)
}

// Get the x509.Certificate stored in the PIV Slot off the chip
func (y Slot) GetCertificate() (*x509.Certificate, error) {
	return y.yubikey.GetCertificate(y.Id)
}

// Write the x509 Certificate to the Yubikey.
func (y *Slot) Update(cert x509.Certificate) error {
	if err := y.yubikey.SaveCertificate(y.Id, cert); err != nil {
		return err
	}

	y.Certificate = &cert
	return nil
}

// vim: foldmethod=marker
