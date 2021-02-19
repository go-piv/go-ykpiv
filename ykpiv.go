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

// XXX: -Wl,--allow-multiple-definition is needed because the test suite fails
//      when I build it. For now this will keep it quiet :\

/*
#cgo pkg-config: ykpiv
#include <ykpiv.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"unsafe"

	"pault.ag/go/ykpiv/internal/bytearray"
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

// Get the Management Key.
//
// On some configurations, users have set the Management Key to a PBKDF2
// SHA1 key derived from the PIN, so this may return one of two things:
//
// If `ManagementKeyIsPIN` is false, the `ManagementKey` byte array
// will be returned.
//
// If `ManagementKeyIsPIN` is true, the `PIN` will be used, in conjunction
// with a salt held within the PIVMON object address to compute the
// ManagementKey. If PIN is nil, this will result in an error being returned.
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

// Get the user defined PUK. This will return an error if PUK is nil.
func (o Options) GetPUK() (string, error) {
	if o.PUK == nil {
		return "", fmt.Errorf("ykpiv: GetPUK: No PUK set in Options")
	}
	return *(o.PUK), nil
}

// Get the user defined PIN. This will return an error if PUK is nil.
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
}

// Write the raw bytes out of a slot stored on the Yubikey. Callers to this
// function should only do so if they understand exactly what data they're
// writnig, what the data should look like, and avoid rebuilding existing
// interfaces if at all possible.
//
// The related method, GetObject, can be used to read data later.
// Care must be taken to ensure the `id` is *not* being used by
// any other applications.
func (y Yubikey) SaveObject(id int32, data []byte) error {
	cData := (*C.uchar)(C.CBytes(data))
	cDataLen := C.size_t(len(data))
	defer C.free(unsafe.Pointer(cData))

	return getError(C.ykpiv_save_object(
		y.state,
		C.int(id),
		cData, cDataLen,
	), "save_object")
}

// Get the raw bytes out of a slot stored on the Yubikey. Callers to this
// function should only do so if they understand exactly what data they're
// reading, what the data should look like, and avoid rebuilding existing
// interfaces if at all possible.
//
// The related method, SaveObject, can be used to write data to be read back
// later. Care must be taken to ensure the `id` is *not* being used by
// any other applications.
func (y Yubikey) GetObject(id int) ([]byte, error) {
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

func (y Yubikey) Serial() (uint32, error) {
	serial := C.uint32_t(0)
	if err := getError(C.ykpiv_get_serial(y.state, &serial), "get_serial"); err != nil {
		return 0, err
	}
	return uint32(serial), nil
}

func (y Yubikey) verify(cPin *C.char) (int, error) {
	tries := C.int(0)
	err := getError(C.ykpiv_verify(y.state, cPin, &tries), "verify")

	if cPin == nil && WrongPIN.Equal(err) {
		return int(tries), nil
	}
	if err != nil {
		return -1, err
	}
	return int(tries), nil
}

func (y Yubikey) SetCHUID(chuid []byte) error {
	cChuid := (*C.ykpiv_cardid)(C.CBytes(chuid))
	defer C.free(unsafe.Pointer(cChuid))
	return getError(C.ykpiv_util_set_cardid(y.state, cChuid), "util_set_cardid")
}

func (y Yubikey) SetCCCID(cccid []byte) error {
	cCccid := (*C.ykpiv_cccid)(C.CBytes(cccid))
	defer C.free(unsafe.Pointer(cCccid))
	return getError(C.ykpiv_util_set_cccid(y.state, cCccid), "util_set_cccid")
}

func (y Yubikey) SetPINPUKRetries(pin string, pintries int, puktries int) error {
	cPin := (*C.char)(C.CString(pin))
	defer C.free(unsafe.Pointer(cPin))

    _, err := y.verify(cPin)
	if err != nil {
		return err
	}

    cPinTries := C.int(pintries)
    cPukTries := C.int(puktries)

    err = getError(C.ykpiv_set_pin_retries(y.state, cPinTries, cPukTries), "set_pin_retries")

    return err
}

// PIN Retries
func (y Yubikey) PINRetries() (int, error) {
	return y.verify(nil)
}

// Log into the Yubikey using the user PIN.
func (y Yubikey) Login() error {
	pin, err := y.options.GetPIN()
	if err != nil {
		return err
	}

	cPin := (*C.char)(C.CString(pin))
	defer C.free(unsafe.Pointer(cPin))
	_, err = y.verify(cPin)
	return err
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

// Attest returns an *x509.Certificate attesting the key in slotId.
// Use it with the attestation certificate in the Attestation slot
// and the Yubico PIV Root CA certificate to verify attestation.
func (y Yubikey) Attest(slotId SlotId) (*x509.Certificate, error) {
	var cDataLen C.size_t = 4096
	var cData *C.uchar = (*C.uchar)(C.malloc(4096))
	defer C.free(unsafe.Pointer(cData))

	if err := getError(C.ykpiv_attest(y.state, C.uchar(slotId.Key), cData, &cDataLen), "attest"); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(C.GoBytes(unsafe.Pointer(cData), C.int(cDataLen)))
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

// sw, data, error
func (y Yubikey) transferData(
	template []byte,
	input []byte,
	maxReturnSize int,
) (int, []byte, error) {
	sw := C.int(0)

	cInputLen := C.long(len(input))
	cInput := (*C.uchar)(C.CBytes(input))
	defer C.free(unsafe.Pointer(cInput))

	cDataLen := C.ulong(maxReturnSize)
	cData := (*C.uchar)(C.malloc(C.size_t(cDataLen)))
	defer C.free(unsafe.Pointer(cData))

	cTemplate := (*C.uchar)(C.CBytes(template))
	defer C.free(unsafe.Pointer(cTemplate))

	if err := getError(C.ykpiv_transfer_data(
		y.state,
		cTemplate,
		cInput, cInputLen,
		cData, &cDataLen,
		&sw,
	), "transfer_data"); err != nil {
		return 0, nil, err
	}

	return int(sw), C.GoBytes(unsafe.Pointer(cData), C.int(cDataLen)), nil
}

// Reset the Yubikey.
//
// This can only be done if both the PIN and PUK have been blocked, and will
// wipe all data on the Key. This includes all Certificates, public and private
// key material.
func (y Yubikey) Reset() error {
	template := []byte{0, C.YKPIV_INS_RESET, 0, 0}
	sw, _, err := y.transferData(template, nil, 128)
	if err != nil {
		return err
	}
	return getSWError(sw, "transfer_data")
}

// ImportKey function imports a private key to the specified slot
func (y Yubikey) ImportKey(slotID SlotId, privKey crypto.PrivateKey) (*Slot, error) {
	var rsaPrivKey rsa.PrivateKey

	switch privKey.(type) {
	case rsa.PrivateKey:
		rsaPrivKey = privKey.(rsa.PrivateKey)

	case *rsa.PrivateKey:
		rsaPrivKey = *(privKey.(*rsa.PrivateKey))

	default:
		return nil, errors.New("ykpiv: ImportKey: non RSA key importing not supported yet")
	}

	var algorithm byte

	switch rsaPrivKey.N.BitLen() {
	case 1024:
		algorithm = C.YKPIV_ALGO_RSA1024

	case 2048:
		algorithm = C.YKPIV_ALGO_RSA2048

	default:
		return nil, fmt.Errorf("ykpiv: ImportKey: Unusable key of %d bits, only 1024 and 2048 are supported", rsaPrivKey.N.BitLen())
	}

	e := big.NewInt(int64(rsaPrivKey.PublicKey.E)).Bytes()
	p := rsaPrivKey.Primes[0].Bytes()
	q := rsaPrivKey.Primes[1].Bytes()
	dp := rsaPrivKey.Precomputed.Dp.Bytes()
	dq := rsaPrivKey.Precomputed.Dq.Bytes()
	qinv := rsaPrivKey.Precomputed.Qinv.Bytes()

	elLen := rsaPrivKey.N.BitLen() / 16

	var _p, _q, _dp, _dq, _qinv *C.uchar

	if len(e) != 3 || e[0] != 0x01 || e[1] != 0x00 || e[2] != 0x01 {
		return nil, errors.New("ykpiv: ImportKey: Invalid public exponent (E) for import (only 0x10001 supported)")
	}

	if len(p) <= elLen {
		_p = (*C.uchar)(C.CBytes(p))
		defer C.free(unsafe.Pointer(_p))
	} else {
		return nil, errors.New("ykpiv: ImportKey: Failed setting P component")
	}

	if len(q) <= elLen {
		_q = (*C.uchar)(C.CBytes(q))
		defer C.free(unsafe.Pointer(_q))
	} else {
		return nil, errors.New("ykpiv: ImportKey: Failed setting Q component")
	}

	if len(dp) <= elLen {
		_dp = (*C.uchar)(C.CBytes(dp))
		defer C.free(unsafe.Pointer(_dp))
	} else {
		return nil, errors.New("ykpiv: ImportKey: Failed setting DP component")
	}

	if len(dq) <= elLen {
		_dq = (*C.uchar)(C.CBytes(dq))
		defer C.free(unsafe.Pointer(_dq))
	} else {
		return nil, errors.New("ykpiv: ImportKey: Failed setting DQ component")
	}

	if len(qinv) <= elLen {
		_qinv = (*C.uchar)(C.CBytes(qinv))
		defer C.free(unsafe.Pointer(_qinv))
	} else {
		return nil, errors.New("ykpiv: ImportKey: Failed setting QINV component")
	}

	if err := getError(C.ykpiv_import_private_key(
		y.state, C.uchar(slotID.Key), C.uchar(algorithm),
		_p, C.size_t(len(p)),
		_q, C.size_t(len(q)),
		_dp, C.size_t(len(dp)),
		_dq, C.size_t(len(dq)),
		_qinv, C.size_t(len(qinv)),
		nil, C.uchar(0),
		C.uchar(0), C.uchar(0),
	), "import_private_key"); err != nil {
		return nil, err
	}

	return &Slot{yubikey: y, Id: slotID, PublicKey: &rsaPrivKey.PublicKey}, nil
}

// Write the x509 Certificate to the Yubikey.
func (y Yubikey) SaveCertificate(slotId SlotId, cert x509.Certificate) error {
	certDer, err := bytearray.Encode([]asn1.RawValue{
		asn1.RawValue{Tag: 0x10, IsCompound: true, Class: 0x01, Bytes: cert.Raw},
		asn1.RawValue{Tag: 0x11, IsCompound: true, Class: 0x01, Bytes: []byte{0x00}},
		asn1.RawValue{Tag: 0x1E, IsCompound: true, Class: 0x03, Bytes: []byte{}},
	})
	if err != nil {
		return err
	}

	return y.SaveObject(slotId.Certificate, certDer)
}

func (y Yubikey) GetCertificate(slotId SlotId) (*x509.Certificate, error) {
	bytes, err := y.GetObject(int(slotId.Certificate))
	if err != nil {
		return nil, err
	}

	objects, err := bytearray.Decode(bytes)
	if err != nil {
		return nil, err
	}

	if len(objects) != 3 && slotId != Attestation {
		return nil, fmt.Errorf("ykpiv: GetCertificate: We expected two der byte arrays from the key")
	}

	return x509.ParseCertificate(objects[0].Bytes)
}

// Create a new Yubikey.
//
// This will use the options in the given `ykpiv.Options` struct to
// find the correct Yubikey, initialize the underlying state, and ensure
// the right bits are set.
func New(opts Options) (*Yubikey, error) {
	var state *C.ykpiv_state
	yubikey := Yubikey{
		state:   state,
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
	var state *C.ykpiv_state

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
