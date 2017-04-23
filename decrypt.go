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
	"io"
	"unsafe"

	"crypto"

	"pault.ag/go/ykpiv/internal/pkcs1v15"
)

func (s Slot) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	// XXX: yank the C.YKPIV_ALGO_RSA2048 out and replace it with a real check
	// on what the slot is under the hood.

	//   ykpiv_rc ykpiv_decipher_data(ykpiv_state *state, const unsigned char *enc_in,
	//                                size_t in_len, unsigned char *enc_out, size_t *out_len,
	//                                unsigned char algorithm, unsigned char key);

	var cMessage = (*C.uchar)(C.CBytes(msg))
	var cMessageLen = C.size_t(len(msg))
	defer C.free(unsafe.Pointer(cMessage))

	var cPlaintextLen = C.size_t(len(msg))
	var cPlaintext = (*C.uchar)(C.malloc(cMessageLen))

	if err := getError(C.ykpiv_decipher_data(
		s.yubikey.state,
		cMessage, cMessageLen,
		cPlaintext, &cPlaintextLen,
		C.YKPIV_ALGO_RSA2048,
		C.uchar(s.id.Key),
	), "decipher_data"); err != nil {
		return nil, err
	}

	return pkcs1v15.Unpad(C.GoBytes(unsafe.Pointer(cPlaintext), C.int(cPlaintextLen)))
}

// vim: foldmethod=marker
