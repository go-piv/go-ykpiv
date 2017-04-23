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
	"io"
	"unsafe"

	"crypto"
)

// It's never a real party until you import both `unsafe`, *and* `crypto`.

// PKCS#1 9.2.1 defines a method to push the hash algorithm used into the
// digest before the signature. More exactly, we prepend some ASN.1 with
// conatins the Obejct ID for the hash algorithm used. Since we know a lot
// about the digest and the OID, we can just prefix the digest with some ASN.1
// fresh off the CPU
var hashOIDs = map[crypto.Hash][]byte{
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},

	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},

	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},

	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
		0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// PKCS#1 1.5 defines a method to pad data passed into a signing operation
// which is (basically) to set some bits at the lower indexes, then a bunch of
// 0xFF, finally, a 0x00, then the data until the end of the block.
func prepareDigestForRSA256(hash crypto.Hash, digest []byte) []byte {
	outputLength := 256
	padding := make([]byte, (outputLength - 3 - len(digest)))
	for i := 0; i < len(padding); i++ {
		padding[i] = 0xFF
	}
	return expandBytes([]byte{0x00, 0x01}, padding, []byte{0x00}, digest)
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

// Sign implements the crypto.Signer.Sign interface.
//
// Unlike other Sign implementations, `rand` will be completely discarded in
// favor of the on-chip RNG.
//
// The output will be a PKCS#1 v1.5 signature over the digest.
func (s Slot) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// XXX: yank the C.YKPIV_ALGO_RSA2048 out and replace it with a real check
	// on what the slot is under the hood.

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("ykpiv: Sign: Digest length doesn't match passed crypto algorithm")
	}

	prefix, ok := hashOIDs[hash]
	if !ok {
		return nil, fmt.Errorf("ykpiv: rsa digest: Unsupported algorithm")
	}
	digest = append(prefix, digest...)

	computedDigest := prepareDigestForRSA256(hash, digest)

	var cDigest = (*C.uchar)(C.CBytes(computedDigest))
	var cDigestLen = C.size_t(len(computedDigest))
	defer C.free(unsafe.Pointer(cDigest))

	var cSignatureLen = C.size_t(1024)
	var cSignature = (*C.uchar)(C.malloc(cSignatureLen))

	if err := getError(C.ykpiv_sign_data(
		s.yubikey.state,
		cDigest, cDigestLen,
		cSignature, &cSignatureLen,

		C.YKPIV_ALGO_RSA2048,
		C.uchar(s.id.Key),
	), "sign_data"); err != nil {
		return nil, err
	}

	return C.GoBytes(unsafe.Pointer(cSignature), C.int(cSignatureLen)), nil
}

// vim: foldmethod=marker
