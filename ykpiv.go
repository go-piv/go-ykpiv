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

	"crypto/x509"
)

// Configuration for initialization of the Yubikey, as well as options that
// may be used during runtime.
type Options struct {

	// When true, this will cause the underlying ykpiv library to emit additional
	// information to stderr. This can be helpful when debugging why something
	// isn't working as expected.
	Verbose bool

	// String to be used when searching for a Yubikey. The comparison
	// will be against the output you can observe from
	// `yubico-piv-tool -a list-readers`.
	Reader string
}

// Encapsulation of the ykpiv internal state object, and the configuration
// in new. This needs to be initalized through `ykpiv.New` to ensure the
// internal state is brought up correctly.
//
// This object represents a single physical yubikey that we've connected to.
// This object provides a number of helper functions hanging off the struct
// to avoid keeping and passing the internal ykpiv state object in C.
//
// `.Close()` must be called, or this will leak memory.
type Yubikey struct {
	state   *C.ykpiv_state
	options Options
}

// Close the Yubikey object, and preform any finization needed to avoid leaking
// memory or holding locks.
func (y Yubikey) Close() error {
	if err := getError(C.ykpiv_disconnect(y.state), "disconnect"); err != nil {
		return err
	}

	if err := getError(C.ykpiv_done(y.state), "done"); err != nil {
		return err
	}

	// This will free the underlying state, no need to C.free the object by
	// hand here

	return nil
}

// Return the ykpiv application version. This is expected to be in the format of
// '1.2.3', but is up to the underlying ykpiv application code.
func (y Yubikey) Version() ([]byte, error) {
	var versionLength = C.size_t(7)

	var version unsafe.Pointer = C.malloc(versionLength)
	defer C.free(version)

	if err := getError(C.ykpiv_get_version(y.state, (*C.char)(version), versionLength), "get_version"); err != nil {
		return nil, err
	}

	return C.GoBytes(version, C.int(versionLength)), nil
}

//
func (y Yubikey) Certificate(slot Slot) (*x509.Certificate, error) {
	var dataLen C.ulong = 3072
	var data *C.uchar = (*C.uchar)(C.malloc(3072))
	defer C.free(unsafe.Pointer(data))

	if err := getError(C.ykpiv_fetch_object(y.state, C.int(slot), data, &dataLen), "fetch_object"); err != nil {
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

// Create a new Yubikey.
//
// This will use the options in the given `ykpiv.Options` struct to
// find the correct Yubikey, initialize the underlying state, and ensure
// the right bits are set.
func New(opts Options) (*Yubikey, error) {
	yubikey := Yubikey{
		state:   &C.ykpiv_state{},
		options: opts,
	}

	verbosity := 0
	if opts.Verbose {
		verbosity = 1
	}

	if C.ykpiv_init(&yubikey.state, C.int(verbosity)) != C.YKPIV_OK {
		return nil, fmt.Errorf("ykpiv: ykpiv_init Failed to connect to reader.")
	}

	something := C.CString(opts.Reader)
	defer C.free(unsafe.Pointer(something))

	if C.ykpiv_connect(yubikey.state, something) != C.YKPIV_OK {
		return nil, fmt.Errorf("ykpiv: ykpiv_connect Failed to connect to reader.")
	}

	return &yubikey, nil
}

// vim: foldmethod=marker
