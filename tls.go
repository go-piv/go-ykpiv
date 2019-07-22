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

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
)

// Create a tls.Certificate fit for use in crypto/tls applications,
// such as net/http, or grpc.
func (slot Slot) TLSCertificate() tls.Certificate {
	var privKey crypto.PrivateKey = slot
	if _, ok := slot.PublicKey.(*ecdsa.PublicKey); ok {
		// ECDSA keys don't implement decryption and crypto/tls will return
		// an error if the private key implements crypto.Decrypter. Hide the
		// Decrypt() method for EC keys.
		privKey = struct{ crypto.Signer }{slot}
	}
	return tls.Certificate{
		Certificate: [][]byte{slot.Certificate.Raw},
		PrivateKey:  privKey,
		Leaf:        slot.Certificate,
	}
}

// vim: foldmethod=marker
