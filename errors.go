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
#cgo darwin LDFLAGS: -L /usr/local/bin -lykpiv
#cgo darwin CFLAGS: -I/usr/local/include/ykpiv/
#cgo linux LDFLAGS: -lykpiv
#cgo linux CFLAGS: -I/usr/include/ykpiv/
#include <ykpiv.h>
*/
import "C"

import (
	"fmt"
)

// Go wrapper around the internal C ykpiv error integers. Error codes as
// they exist in ykpiv.h are brought into Go, since we can add some additional
// context around them, as well as implement the Error interface.
type Error struct {

	// int representing the underlying error code as ykpiv had given us. The
	// exact numbers can be found in your local ykpiv.h, inside the ykpiv_rc
	// enum.
	Code int

	// Human readable message regarding what happened.
	Message string

	// internal marker to know where this fell out of. it's helpful to know if
	// this came out of ykpiv_sign_data or ykpiv_done
	where string
}

// Check to see if another Error is the same as our struct. This compares
// the underlying Code integer.
func (e Error) Equal(err error) bool {
	otherError, ok := err.(Error)
	if !ok {
		return false
	}
	return e.Code == otherError.Code
}

// Error interface. This will sprintf a string containing where this error
// came from, the human message, and the underlying ykpiv code, to aid with
// debugging.
func (e Error) Error() string {
	return fmt.Sprintf("%s: %s (%d) - %s", e.where, e.Message, e.Code,
		C.GoString(C.ykpiv_strerror(C.ykpiv_rc(e.Code))))
}

// Create a helpful mapping between 8 bit integers and the Error that it
// belongs to. This is used to look errors up at runtime later.
func createErrorLookupMap(errs ...Error) map[int]Error {
	ret := map[int]Error{}
	for _, err := range errs {
		ret[err.Code] = err
	}
	return ret
}

var (
	MemoryError         = Error{Code: C.YKPIV_MEMORY_ERROR, Message: "Memory Error"}
	PCSCError           = Error{Code: C.YKPIV_PCSC_ERROR, Message: "PKCS Error"}
	SizeError           = Error{Code: C.YKPIV_SIZE_ERROR, Message: "Size Error"}
	AppletError         = Error{Code: C.YKPIV_APPLET_ERROR, Message: "Applet Error"}
	AuthenticationError = Error{Code: C.YKPIV_AUTHENTICATION_ERROR, Message: "Authentication Error"}
	RandomnessError     = Error{Code: C.YKPIV_RANDOMNESS_ERROR, Message: "Randomness Error"}
	GenericError        = Error{Code: C.YKPIV_GENERIC_ERROR, Message: "Generic Error"}
	KeyError            = Error{Code: C.YKPIV_KEY_ERROR, Message: "Key Error"}
	ParseError          = Error{Code: C.YKPIV_PARSE_ERROR, Message: "Parse Error"}
	WrongPIN            = Error{Code: C.YKPIV_WRONG_PIN, Message: "Wrong PIN"}
	InvalidObject       = Error{Code: C.YKPIV_INVALID_OBJECT, Message: "Invalid Object"}
	AlgorithmError      = Error{Code: C.YKPIV_ALGORITHM_ERROR, Message: "Algorithm Error"}
	PINLockedError      = Error{Code: C.YKPIV_PIN_LOCKED, Message: "PIN Locked"}

	SecurityStatusError = Error{Code: C.SW_ERR_SECURITY_STATUS, Message: "Security Status Error"}
	AuthBlocked         = Error{Code: C.SW_ERR_AUTH_BLOCKED, Message: "Auth Blocked"}
	IncorrectParam      = Error{Code: C.SW_ERR_INCORRECT_PARAM, Message: "Incorrect Param"}
	IncorrectSlot       = Error{Code: C.SW_ERR_INCORRECT_SLOT, Message: "Incorrect Slot"}

	errorLookupMap = createErrorLookupMap(MemoryError, PCSCError, SizeError, AppletError,
		AuthenticationError, RandomnessError, GenericError, KeyError, ParseError,
		WrongPIN, InvalidObject, AlgorithmError, PINLockedError)

	swErrorLookupMap = createErrorLookupMap(SecurityStatusError, AuthBlocked,
		IncorrectParam, IncorrectSlot)
)

// Take a ykpiv_rc return code and turn it into a ykpiv.Error.
func getError(whoops C.ykpiv_rc, name string) error {
	if err, ok := errorLookupMap[int(whoops)]; ok {
		err.where = fmt.Sprintf("ykpiv ykpiv_%s", name)
		return err
	}
	return nil
}

// Take a ykpiv_rc return code and turn it into a ykpiv.Error.
func getSWError(whoops int, name string) error {
	if err, ok := swErrorLookupMap[int(whoops)]; ok {
		err.where = fmt.Sprintf("ykpiv sw ykpiv_%s", name)
		return err
	}
	return nil
}

// vim: foldmethod=marker
