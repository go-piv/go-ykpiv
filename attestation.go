// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2019
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
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

var yubicoPivAttestationCAs = [][]byte{
	[]byte(`
-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----
`),
}

var (
	// OIDs of some Yubikey specific fields. These are present on the forms
	// of a Yubikey Attestion Certificate.
	oidFirmwareVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerialNumber    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}

	// This is not implemented; I don't have hardware that returns a Certificate
	// that has this Extension. This can be implemented once we get an example.
	oidFormFactor = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}
)

// Verify that the attestation certificate is correctly signed by the roots in `options`
//
// Verify that Attested Certificate is signed by that Attestation Certificate
//
// The `attestationCert` is the Certificate from the Yubikey Attestation slot,
// signed by the provided roots. It should not be a CA Certificate in most cases.
//
// The `attestedCert` is the Certificate signed by the Attestation slot asserting
// that the public key was generated on-chip.
//
// The `options` is the set of roots and verification assertions to use when checking
// the `attestationCert` and `attestedCert`.
func VerifyAttestationWithOptions(attestationCert, attestedCert *x509.Certificate, options x509.VerifyOptions) (verifiedChains [][]*x509.Certificate, err error) {
	var attestationChains [][]*x509.Certificate

	// Verify Attestation Cert against using the verify options
	if attestationChains, err = attestationCert.Verify(options); err != nil {
		return
	}

	// Initialize intermediate chains if necessary
	if options.Intermediates == nil {
		options.Intermediates = x509.NewCertPool()
	}

	if attestationCert.IsCA {
		// Add Attestation Certificate to Trust Store
		options.Intermediates.AddCert(attestationCert)
		verifiedChains, err = attestedCert.Verify(options)
	} else {
		// Note we cannot use CheckSignatureFrom because the parent is not a CA
		err = attestationCert.CheckSignature(attestedCert.SignatureAlgorithm,
			attestedCert.RawTBSCertificate,
			attestedCert.Signature)
		// Build chains from the verified attestationChains extending each with
		// the attested certificate
		if err == nil {
			for i := 0; i < len(attestationChains); i++ {
				attestationChains[i] = append([]*x509.Certificate{attestedCert}, attestationChains[i]...)
			}
			verifiedChains = attestationChains
		}
	}
	return
}

// Verify that the attestation certificate is correctly signed by the Yubikey
// root (provided with this package), as well as verifying that the Attestation
// Certificate is signed by that slot correctly.
//
// The `attestationCert` is the Certificate from the Yubikey Attestation slot, signed by
// the Yubico roots. It is not a CA certificate from Yubico.
//
// The `attestedCert` is the Certificate signed by the Attestation slot asserting
// that the public key was generated on-chip.
func VerifyAttestation(attestationCert, attestedCert *x509.Certificate) ([][]*x509.Certificate, error) {
	options := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}

	for _, yubicoPivAttestationCA := range yubicoPivAttestationCAs {
		block, _ := pem.Decode(yubicoPivAttestationCA)
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !caCert.IsCA {
			return nil, fmt.Errorf("ykpiv: INTERNAL ERROR: Attestation Root PEM is wrong!")
		}
		if bytes.Equal(caCert.RawIssuer, caCert.RawSubject) {
			options.Roots.AddCert(caCert)
		} else {
			options.Intermediates.AddCert(caCert)
		}
	}

	return VerifyAttestationWithOptions(attestationCert, attestedCert, options)
}

// Struct with an anonymous member (`x509.Certificate`) that allows you to
// both access the regular fields for ease of use, as well as handle the
// Yubikey particular fields.
type AttestionCertificate struct {
	x509.Certificate

	// Version of the Yubikey Firmware that generated this key.
	FirmwareVersion *[3]byte

	// Serial Number of the Yubikey in question.
	SerialNumber *int

	//
	PinPolicy   *byte
	TouchPolicy *byte
}

// Parse the Yubikey specific Extensions from the x509.Certificate, and place
// them into a struct for use by end users.
func NewAttestionCertificate(cert *x509.Certificate) (*AttestionCertificate, error) {
	aC := AttestionCertificate{Certificate: *cert}

	for _, extension := range aC.Extensions {
		switch {
		case extension.Id.Equal(oidFirmwareVersion):
			firmware := [3]byte{
				extension.Value[0],
				extension.Value[1],
				extension.Value[2],
			}
			aC.FirmwareVersion = &firmware
			break
		case extension.Id.Equal(oidSerialNumber):
			var serial int = 0
			if _, err := asn1.Unmarshal(extension.Value, &serial); err != nil {
				return nil, err
			}
			aC.SerialNumber = &serial
			break
		case extension.Id.Equal(oidPolicy):
			var (
				pin   byte = extension.Value[0]
				touch byte = extension.Value[1]
			)
			aC.PinPolicy = &pin
			aC.TouchPolicy = &touch
			break
		}
	}

	return &aC, nil
}

// vim: foldmethod=marker
