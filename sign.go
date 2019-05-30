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
	"io"
	"unsafe"

	"crypto"

	"pault.ag/go/ykpiv/internal/pkcs1v15"
)

// It's never a real party until you import both `unsafe`, *and* `crypto`.

// PKCS#1 9.2.1 defines a method to push the hash algorithm used into the
// digest before the signature. More exactly, we prepend some ASN.1 with
// contains the Object ID for the hash algorithm used. Since we know a lot
// about the digest and the OID, we can just prefix the digest with some ASN.1
// fresh off the CPU
var hashOIDs = map[crypto.Hash][]byte{
	crypto.SHA1: {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
		0x1a, 0x05, 0x00, 0x04, 0x14},

	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},

	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},

	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},

	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// Sign implements the crypto.Signer.Sign interface.
//
// Unlike other Sign implementations, `rand` will be completely discarded in
// favor of the on-chip RNG.
//
// The output will be a PKCS#1 v1.5 signature (for RSA) or ECDSA signature (for EC keys) over the digest.
func (s Slot) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algorithm, err := s.getAlgorithm()
	if err != nil {
		return nil, err
	}

	switch algorithm {
	case C.YKPIV_ALGO_RSA1024:
		return s.signRsa(digest, opts, algorithm)
	case C.YKPIV_ALGO_RSA2048:
		return s.signRsa(digest, opts, algorithm)
	case C.YKPIV_ALGO_ECCP256:
		return s.signEcdsa(digest, opts, algorithm)
	case C.YKPIV_ALGO_ECCP384:
		return s.signEcdsa(digest, opts, algorithm)
	default:
		return nil, fmt.Errorf("ykpiv: Sign: Unsupported algorithm")
	}

}

func (s Slot) signRsa(digest []byte, opts crypto.SignerOpts, algorithm C.uchar) ([]byte, error) {

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("ykpiv: Sign: Digest length doesn't match passed crypto algorithm")
	}

	prefix, ok := hashOIDs[hash]
	if !ok {
		return nil, fmt.Errorf("ykpiv: Sign: Unsupported algorithm")
	}
	digest = append(prefix, digest...)

	var computedDigest []byte
	switch algorithm {
	case C.YKPIV_ALGO_RSA1024:
		computedDigest = pkcs1v15.Pad(digest, 128)
	case C.YKPIV_ALGO_RSA2048:
		computedDigest = pkcs1v15.Pad(digest, 256)
	default:
		return nil, fmt.Errorf("ykpiv: Sign: Can't preform padding for signature, unknown algorithm")
	}

	var cDigestLen = C.size_t(len(computedDigest))
	var cDigest = (*C.uchar)(C.CBytes(computedDigest))
	defer C.free(unsafe.Pointer(cDigest))

	var cSignatureLen = C.size_t(1024)
	var cSignature = (*C.uchar)(C.malloc(cSignatureLen))
	defer C.free(unsafe.Pointer(cSignature))

	if err := getError(C.ykpiv_sign_data(
		s.yubikey.state,
		cDigest, cDigestLen,
		cSignature, &cSignatureLen,

		algorithm,
		C.uchar(s.Id.Key),
	), "sign_data"); err != nil {
		return nil, err
	}

	return C.GoBytes(unsafe.Pointer(cSignature), C.int(cSignatureLen)), nil
}

func (s Slot) signEcdsa(digest []byte, opts crypto.SignerOpts, algorithm C.uchar) ([]byte, error) {

	var curveSizeBytes int
	switch algorithm {
	case C.YKPIV_ALGO_ECCP256:
		curveSizeBytes = 32
	case C.YKPIV_ALGO_ECCP384:
		curveSizeBytes = 48
	default:
		return nil, fmt.Errorf("ykpiv: Sign: Can't perform ECDSA signature, unknown algorithm")
	}

	var computedDigest []byte
	if len(digest) > curveSizeBytes {
		computedDigest = digest[:curveSizeBytes]
	} else {
		computedDigest = digest
	}

	var cDigestLen = C.size_t(len(computedDigest))
	var cDigest = (*C.uchar)(C.CBytes(computedDigest))
	defer C.free(unsafe.Pointer(cDigest))

	var cSignatureLen = C.size_t(1024)
	var cSignature = (*C.uchar)(C.malloc(cSignatureLen))
	defer C.free(unsafe.Pointer(cSignature))

	if err := getError(C.ykpiv_sign_data(
		s.yubikey.state,
		cDigest, cDigestLen,
		cSignature, &cSignatureLen,

		algorithm,
		C.uchar(s.Id.Key),
	), "sign_data"); err != nil {
		return nil, err
	}

	return C.GoBytes(unsafe.Pointer(cSignature), C.int(cSignatureLen)), nil
}

// vim: foldmethod=marker
