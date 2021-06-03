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
	"encoding/pem"
	"fmt"
	"testing"
)

const attestationYubikeySerialNumber = 10231423

var attestationYubikeyFirmwareVersion = [3]byte{4, 4, 5}

var signedAttestationCertificateBytes = []byte(`
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIQd0/a+pvTa80F6ay2xtNe2DANBgkqhkiG9w0BAQsFADAh
MR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw
MFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl
c3RhdGlvbiA5YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKLnq2Yu
qgFjcjODfIQSsY9n4LffK1b/ITagzqmSabdoua0EcjupUwvsVY+f9nybkcxEv7a6
/FNUznKwR+j9LU3yOTHwSzZy6+6Eoc0w2DZ/6ggrsz8ICOe/wB2i8nFv8LH/szAP
3nL70xjvql8a8DScILPVqz+RCzuoXmEfzuY5iqQuI3sLQhpE/SXO7tYRT5l+BZMr
PJ0Td9AWDYjmGX2m1q0AtfjuDP0TCeAwRlMcNFgoQxrE33aqeA5mi+qWSsIpINJX
2PlORqQHIofTqUCq4/P8Y5zWs3krPycbKaGc/x07WMJ+ac1fteMjsai+RsYTfTbF
73yTITLWTqJaLMcCAwEAAaM9MDswEQYKKwYBBAGCxAoDAwQDBAQFMBQGCisGAQQB
gsQKAwcEBgIEAJwefzAQBgorBgEEAYLECgMIBAICATANBgkqhkiG9w0BAQsFAAOC
AQEABGzBTBgzcflFKKdjqL+Hyh/cCl09gPBck/mpLa9o4YeKeNRFSdVofSJ1YnmP
ltciN2oamD0z+g02Z1udgVY3Xqptf9VrclcLJdsxMIo6aM20QfamhhK4LOlvkims
gXjulDxANyileK9uyqjDEh0LIR+1MqWXxyfbKFN7WTU3cyp9rcpn/ggKyLOISq2B
JMWletqwlbVLrIbFGM//7OzA2OIYW81bCEWz/VNbS+7nWxbka/plVkj9+kNNP+DW
aYWzgkUf4rX41yjrytwX+Ls8ZRfXLqgJg2AXvYLFRaTtFkhvZpo+nZzpnK+66vDY
L8W17VuxdCpie3DAcevXM733Ig==
-----END CERTIFICATE-----
`)

var attestationSigningCertificateBytes = []byte(`
-----BEGIN CERTIFICATE-----
MIIC5jCCAc6gAwIBAgIJAP0poKlkCZhmMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV
BAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw
MDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0
dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3oC+9KvX
dxybNoky+Ymhoq6NMK0QYDqqaLHuhySiXgtTCXUHpRmc7Kymht01pMgKmzpiF2qT
BiL4gzp/a/buDJar0kHtlZ3KQ8cGUDbGHz1TvABr6w6qVwvX1MrB5TjpUh9/Jwcm
01dj50Pn4XMYXTioGOD63aviocgCBlEHepYXeH+jhAWsGrAuijgezvaZygEp1OuW
C6Oed2/KAmXEDNt/AA/EzkixczEFGolcvkOGpeLCuhSS9VW/5AmLCDSAyrc4yhmJ
maUnAvlqRpVm0iuz9dVqPDDytktSuZr17sBMstmn+ahQibNWCr+pY7AGuj4hYPG/
JIPhPg4B5vz5mQIDAQABoxUwEzARBgorBgEEAYLECgMDBAMEBAUwDQYJKoZIhvcN
AQELBQADggEBAIu4Omxh4XsCif2dqHytKmFAYDkL61LksIl1BG/9vFjM8De1Q/FG
gfqVwAsYXmcLdRn6e6qGmc9sM22gOXLecNJkiUl56Th3b9bH1/DuXuXsrZLRE/6L
oge3XjyBRUMmlEVLdpLBIAu7IQXj5fMiPL5VvNluFcVTOQaUwV/HUFdpcQmW3wxj
FlbyGetX9pqLnw3XH5C86cej5TXFbWu1nLrpAbYE41OUjM6BSdekrKWJHFKdcCBU
ztdH0PRnJDab60YKqgVRKc+IViSoIpfb7xLpukZa2Mtf6AQcDsSL2y5sQvAmem4N
/KUBNX42RH9YKr9Tmq5DHA2CspVwEyygilk=
-----END CERTIFICATE-----
`)

func parsePem(pemBytes []byte) (*x509.Certificate, error) {
	parsed, _ := pem.Decode(pemBytes)
	if parsed == nil {
		return nil, fmt.Errorf("could not parse pem block")
	}
	return x509.ParseCertificate(parsed.Bytes)
}

func TestVerifyAttestation(t *testing.T) {
	signedCertificate, err := parsePem(signedAttestationCertificateBytes)
	if err != nil {
		t.Fatalf("could not parse attested certificate %s", err)
	}
	signingCertificate, err := parsePem(attestationSigningCertificateBytes)
	if err != nil {
		t.Fatalf("could not parse attestation certificate %s", err)
	}
	chains, err := VerifyAttestation(signingCertificate, signedCertificate)
	if err != nil {
		t.Fatalf("could not verify attested certificate %s", err)
	}
	for ichain, chain := range chains {
		t.Log("attestation certificate verified chain:")
		for icert, cert := range chain {
			t.Logf("[%d][%d]: %s", ichain, icert, cert.Subject.CommonName)
		}
	}
	attestationCertificate, err := NewAttestionCertificate(signedCertificate)
	if err != nil {
		t.Fatalf("could not parse attestation certificate %s", err)
	}
	if attestationCertificate.SerialNumber == nil {
		t.Fatal("serial number present but not decoded")
	}
	if *attestationCertificate.SerialNumber != attestationYubikeySerialNumber {
		t.Fatalf("decoded serial number %d did not match %d", *attestationCertificate.SerialNumber, attestationYubikeySerialNumber)
	}
	if attestationCertificate.FirmwareVersion == nil {
		t.Fatal("firmware version present but not decoded")
	}
	if bytes.Compare((*attestationCertificate.FirmwareVersion)[:], attestationYubikeyFirmwareVersion[:]) != 0 {
		t.Fatalf("decoded firmware version %v did not match expected version %v", *attestationCertificate.FirmwareVersion, attestationYubikeyFirmwareVersion)
	}
}

// vim: foldmethod=marker