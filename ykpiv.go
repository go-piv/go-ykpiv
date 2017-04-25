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
	"bytes"
	"fmt"
	"unsafe"
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

	// PIN is the pin that will be used when logging in
	PIN *string

	// PUK is the PUK to be used when logging in
	PUK *string

	// ManagementKey is the Management Key to be used for key operations
	ManagementKey []byte

	// Flag to let ykpiv know if this PIV token has a ManagementKey that was
	// set by pivman, which is a PBKDF2 SHA1 key derived with a salt held on
	// chip in the internal pivman data.
	//
	// If this is `true`, ManagementKey will be ignored in favor of deriving
	// the key from the PIN.
	ManagementKeyIsPIN bool
}

func (o Options) GetManagementKey(y Yubikey) ([]byte, error) {
	key := o.ManagementKey
	if o.ManagementKeyIsPIN {
		var err error
		key, err = y.deriveManagementKey()
		if err != nil {
			return nil, err
		}
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("ykpiv: GetManagementKey: ManagementKey is empty!")
	}
	return key, nil
}

func (o Options) GetPUK() (string, error) {
	if o.PUK == nil {
		return "", fmt.Errorf("ykpiv: GetPUK: No PUK set in Options")
	}
	return *(o.PUK), nil
}

func (o Options) GetPIN() (string, error) {
	if o.PIN == nil {
		return "", fmt.Errorf("ykpiv: GetPIN: No PIN set in Options")
	}
	return *(o.PIN), nil
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

	return getError(C.ykpiv_done(y.state), "done")

	// calling ykpiv_done will free the underlying ykpiv_state. Doing a C.free
	// here will result in a double-free, but thanks for noticing and keeping
	// memory tidy!
	return nil
}

// get an object in the Yubikey
func (y Yubikey) getObject(id int) ([]byte, error) {
	var cDataLen C.ulong = 4096
	var cData *C.uchar = (*C.uchar)(C.malloc(4096))
	defer C.free(unsafe.Pointer(cData))

	if err := getError(C.ykpiv_fetch_object(y.state, C.int(id), cData, &cDataLen), "fetch_object"); err != nil {
		return nil, err
	}

	return C.GoBytes(unsafe.Pointer(cData), C.int(cDataLen)), nil
}

// Return the ykpiv application version. This is expected to be in the format of
// '1.2.3', but is up to the underlying ykpiv application code.
func (y Yubikey) Version() ([]byte, error) {

	var cVersionLen C.size_t = C.size_t(7)
	var cVersion *C.char = (*C.char)(C.malloc(cVersionLen))
	defer C.free(unsafe.Pointer(cVersion))

	if err := getError(C.ykpiv_get_version(y.state, cVersion, cVersionLen), "get_version"); err != nil {
		return nil, err
	}

	return C.GoBytes(unsafe.Pointer(cVersion), C.int(cVersionLen)), nil
}

// Log into the Yubikey using the user PIN.
func (y Yubikey) Login() error {
	pin, err := y.options.GetPIN()
	if err != nil {
		return err
	}

	tries := C.int(0)
	cPin := (*C.char)(C.CString(pin))
	defer C.free(unsafe.Pointer(cPin))
	return getError(C.ykpiv_verify(y.state, cPin, &tries), "verify")
}

// Using the PUK, unblock the PIN, resetting the retry counter.
func (y Yubikey) UnblockPIN(newPin string) error {
	tries := C.int(0)
	puk, err := y.options.GetPUK()
	if err != nil {
		return err
	}

	cPuk := (*C.char)(C.CString(puk))
	cPukLen := C.size_t(len(puk))
	defer C.free(unsafe.Pointer(cPuk))

	cPin := (*C.char)(C.CString(newPin))
	cPinLen := C.size_t(len(newPin))
	defer C.free(unsafe.Pointer(cPin))

	return getError(C.ykpiv_unblock_pin(
		y.state,
		cPuk, cPukLen,
		cPin, cPinLen,
		&tries,
	), "change_puk")
}

// Change the PUK.
func (y Yubikey) ChangePUK(newPuk string) error {
	if y.options.ManagementKeyIsPIN {
		return fmt.Errorf("ykpiv: ChangePIN: Please change your PUK through pivman")
	}

	tries := C.int(0)
	puk, err := y.options.GetPUK()
	if err != nil {
		return err
	}

	cOldPuk := (*C.char)(C.CString(puk))
	cOldPukLen := C.size_t(len(puk))
	defer C.free(unsafe.Pointer(cOldPuk))

	cNewPuk := (*C.char)(C.CString(newPuk))
	cNewPukLen := C.size_t(len(newPuk))
	defer C.free(unsafe.Pointer(cNewPuk))

	return getError(C.ykpiv_change_puk(
		y.state,
		cOldPuk, cOldPukLen,
		cNewPuk, cNewPukLen,
		&tries,
	), "change_puk")
}

// Set the Yubikey Management Key. The Management key is a 24 byte
// key that's used as a 3DES key internally to preform key operations,
// such as Certificate import, or keypair generation.
func (y Yubikey) SetMGMKey(key []byte) error {
	if y.options.ManagementKeyIsPIN {
		return fmt.Errorf("ykpiv: ChangePIN: Please change your Management Key through pivman")
	}

	cMgmKey := (*C.uchar)(C.CBytes(key))
	defer C.free(unsafe.Pointer(cMgmKey))
	return getError(C.ykpiv_set_mgmkey(y.state, cMgmKey), "set_mgmkey")
}

// Change your PIN on the Yubikey from the oldPin to the newPin.
func (y Yubikey) ChangePIN(oldPin, newPin string) error {
	if y.options.ManagementKeyIsPIN {
		return fmt.Errorf("ykpiv: ChangePIN: Please change your PIN through pivman")
	}

	tries := C.int(0)

	cOldPin := (*C.char)(C.CString(oldPin))
	cOldPinLen := C.size_t(len(oldPin))
	defer C.free(unsafe.Pointer(cOldPin))

	cNewPin := (*C.char)(C.CString(newPin))
	cNewPinLen := C.size_t(len(newPin))
	defer C.free(unsafe.Pointer(cNewPin))

	return getError(C.ykpiv_change_pin(
		y.state,
		cOldPin, cOldPinLen,
		cNewPin, cNewPinLen,
		&tries,
	), "change_pin")
}

// Authenticate to the Yubikey using the Management Key. This key is a 24 byte
// key that's used as a 3DES key internally to write new Certificates, or
// create a new keypair.
func (y Yubikey) Authenticate() error {
	managementKey, err := y.options.GetManagementKey(y)
	if err != nil {
		return err
	}

	cKey := (*C.uchar)(C.CBytes(managementKey))
	defer C.free(unsafe.Pointer(cKey))

	return getError(C.ykpiv_authenticate(y.state, cKey), "authenticate")
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

	if err := getError(C.ykpiv_init(&yubikey.state, C.int(verbosity)), "init"); err != nil {
		return nil, err
	}

	something := C.CString(opts.Reader)
	defer C.free(unsafe.Pointer(something))

	if err := getError(C.ykpiv_connect(yubikey.state, something), "connect"); err != nil {
		return nil, err
	}

	return &yubikey, nil
}

// Get a list of strings that the ykpiv library has identified as unique ways
// to fetch every reader attached to the system. This can be handy to define a
// "Reader" argument in ykpiv.Options, and may include things ykpiv can't talk
// to.
func Readers() ([]string, error) {
	state := &C.ykpiv_state{}

	if err := getError(C.ykpiv_init(&state, C.int(0)), "init"); err != nil {
		return nil, err
	}

	var cReadersLen = C.size_t(2048)
	var cReaders *C.char = (*C.char)(C.malloc(cReadersLen))
	defer C.free(unsafe.Pointer(cReaders))

	if err := getError(C.ykpiv_list_readers(state, cReaders, &cReadersLen), "list_readers"); err != nil {
		return nil, err
	}

	readerBytes := C.GoBytes(unsafe.Pointer(cReaders), C.int(cReadersLen))
	readers := []string{}

	for _, reader := range bytes.Split(readerBytes, []byte{0x00}) {
		if len(reader) == 0 {
			continue
		}
		readers = append(readers, string(reader))
	}

	if err := getError(C.ykpiv_done(state), "done"); err != nil {
		return nil, err
	}

	return readers, nil
}

// vim: foldmethod=marker
