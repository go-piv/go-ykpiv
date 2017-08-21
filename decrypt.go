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
	"io"
	"unsafe"

	"crypto"

	"pault.ag/go/ykpiv/internal/pkcs1v15"
)

// Decrypt decrypts ciphertext with the private key backing the Slot we're operating
// on. This implements the crypto.Decrypter interface.
//
// The `rand` argument is disregarded in favor of the on-chip RNG on the Yubikey
// The `opts` argument is not used at this time, but may in the future.
func (s Slot) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	var cMessage = (*C.uchar)(C.CBytes(msg))
	defer C.free(unsafe.Pointer(cMessage))
	var cMessageLen = C.size_t(len(msg))

	var cPlaintextLen = C.size_t(len(msg))
	var cPlaintext = (*C.uchar)(C.malloc(cMessageLen))
	defer C.free(unsafe.Pointer(cPlaintext))

	algorithm, err := s.getAlgorithm()
	if err != nil {
		return nil, err
	}

	if err := getError(C.ykpiv_decipher_data(
		s.yubikey.state,
		cMessage, cMessageLen,
		cPlaintext, &cPlaintextLen,
		algorithm,
		C.uchar(s.Id.Key),
	), "decipher_data"); err != nil {
		return nil, err
	}

	return pkcs1v15.Unpad(C.GoBytes(unsafe.Pointer(cPlaintext), C.int(cPlaintextLen)))
}

// vim: foldmethod=marker
