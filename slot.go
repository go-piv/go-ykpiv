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

	"crypto"
	"crypto/x509"

	"unsafe"
)

// Slot ID (0x9a, etc) {{{

type SlotId struct {
	Certificate int32
	Key         int32
}

func (s SlotId) String() string {
	return fmt.Sprintf("Slot key=%x", s.Key)
}

var (
	Authentication SlotId = SlotId{
		Certificate: C.YKPIV_OBJ_AUTHENTICATION,
		Key:         C.YKPIV_KEY_AUTHENTICATION,
	}
)

// }}}

type Slot struct {
	yubikey     Yubikey
	id          SlotId
	certificate x509.Certificate
}

func (y Yubikey) Authentication() (*Slot, error) {
	return y.Slot(Authentication)
}

func (y Yubikey) Slot(id SlotId) (*Slot, error) {
	/* Right, let's see what we can do here */
	slot := Slot{yubikey: y, id: id}

	certificate, err := slot.Certificate()
	if err != nil {
		return nil, err
	}
	slot.certificate = *certificate
	return &slot, nil
}

func (s Slot) Public() crypto.PublicKey {
	return s.certificate.PublicKey
}

func (s Slot) Id() SlotId {
	return s.id
}

func (y Slot) Certificate() (*x509.Certificate, error) {
	var dataLen C.ulong = 3072
	var data *C.uchar = (*C.uchar)(C.malloc(3072))
	defer C.free(unsafe.Pointer(data))

	if err := getError(C.ykpiv_fetch_object(y.yubikey.state, C.int(y.id.Certificate), data, &dataLen), "fetch_object"); err != nil {
		return nil, err
	}

	// some magic shit going down here. I'm not exactly sure what. This needs
	// a metric fuckload of testing. There's some sort of length encoding
	// in the underlying string. My guess is the DER that I've got back
	// falls into the same general length and never triggered some voodoo
	// with dynamic length byte prefixes. There's a p. good chance this is
	// just outright wrong.
	der := C.GoBytes(unsafe.Pointer(data), C.int(dataLen))[4 : dataLen-5]

	// If this is throwing sequence truncated and/or trailing byte errors
	// the first thing to double check is the byte mangling above, and
	// if the comment above applies to this.
	return x509.ParseCertificate(der)
}

// vim: foldmethod=marker
