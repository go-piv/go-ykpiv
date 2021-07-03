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
	"time"
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

var customSignedAttestationCertificateBytes = []byte(`
-----BEGIN CERTIFICATE-----
MIICbzCCAfSgAwIBAgIRAOnRQVt+bbLswgq1eVA2dhcwCgYIKoZIzj0EAwIwIjEg
MB4GA1UEAxMXWXViaWtleSBQSVYgQXR0ZXN0YXRpb24wHhcNMjEwNzAyMjMyNjIw
WhcNMjIwNzAyMjMyNzIwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRlc3Rh
dGlvbiA5YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOOpKaDcPU/E
CQl1oiJaP7dHR1hjQuRBatxk0XpctBENLgOH5kPBm6kV1lV1ocEJ7lR9lDmA0lb8
HcNPfovan5rIJR7fRkIpMFxOQQlk+pv8Fz618JTwVP83nG6b+FjRDrAiqYKgECHO
uUkklrSMiE/wpS5Whcb8/sMmoDT3BY2IplYJt7Bn5tZ4XesfcLfyrks7+6jqVhPY
B3oc/59rXcXVKgP0fxIDgonzw75vgTzfaFi1dU+fv2UeWleI+MAnpc8e4fQfrYgO
3MRK58KrkHJ30455u/fggBLdU5SK2vyodB4DfUJnFtosTiN1cGyjgvoCp+I8rrtu
4Ci27d0S8HkCAwEAAaM9MDswEQYKKwYBBAGCxAoDAwQDBAQFMBQGCisGAQQBgsQK
AwcEBgIEAJwefzAQBgorBgEEAYLECgMIBAICATAKBggqhkjOPQQDAgNpADBmAjEA
i7jSnotfEXX5n1U18iDfdLiFn7je3qxX0iNYNhrMeHJX2TSA1qBLn7VIHeEv2uIn
AjEAgwMRfyYvQPrbcOf2cOeYAQ86LH/fdQqOb8Yn7i6qqT3RhRN0eIhJwjgCXL8b
8Qmz
-----END CERTIFICATE-----
`)

var customAttestationSigningCertificateBytes = []byte(`
-----BEGIN CERTIFICATE-----
MIICejCCAiCgAwIBAgIRANq8x4/ed0VADwwfIViCziwwCgYIKoZIzj0EAwIwZDEo
MCYGA1UEChMfU21hbGxzdGVwIENlcnRpZmljYXRlIEF1dGhvcml0eTE4MDYGA1UE
AxMvU21hbGxzdGVwIENlcnRpZmljYXRlIEF1dGhvcml0eSBJbnRlcm1lZGlhdGUg
Q0EwHhcNMjEwNzAyMjMyNjIwWhcNMjIwNzAyMjMyNzIwWjAiMSAwHgYDVQQDExdZ
dWJpa2V5IFBJViBBdHRlc3RhdGlvbjB2MBAGByqGSM49AgEGBSuBBAAiA2IABMPx
QDGvyewygsqTEd86ueYrBP5ww0102fB2sOG8IUNlJ5KktZVEehFl7FIVbjsQGUnq
JCGafe2eXvDJC5osc0cX7BceV1ZfXnvPPquO47px2QtqBPuyh8qv09C2tzjapaOB
1zCB1DAOBgNVHQ8BAf8EBAMCBkAwHQYDVR0OBBYEFMSGFvGO4rke9hI1geRK1oEM
YCDeMB8GA1UdIwQYMBaAFMryYsrYO0gHSi1e+IB697G/usLuMCIGA1UdEQQbMBmC
F1l1YmlrZXkgUElWIEF0dGVzdGF0aW9uMF4GDCsGAQQBgqRkxihAAQROMEwCAQEE
GmJsdWVzdGVhbHRoQGJsdWVzdGVhbHRoLnB3BCtxTFByY3lmdU5Vdi1Yd2IyckVJ
SkRFLTNDXy12NzdWZUQ4OWhzdk8wemVRMAoGCCqGSM49BAMCA0gAMEUCICyFrut1
QxhMJ/idYC6SSQTBnCf9q77vZl4er7TvqRblAiEAkRQVVu5X+hKLHhLeUFqSevtr
l9cXKAJWCZuLJERHKAY=
-----END CERTIFICATE-----
`)

var customCABytes = [][]byte{
	[]byte(`
-----BEGIN CERTIFICATE-----
MIICJTCCAcugAwIBAgIRAOahmSGjdYIOokeTskTboO8wCgYIKoZIzj0EAwIwXDEo
MCYGA1UEChMfU21hbGxzdGVwIENlcnRpZmljYXRlIEF1dGhvcml0eTEwMC4GA1UE
AxMnU21hbGxzdGVwIENlcnRpZmljYXRlIEF1dGhvcml0eSBSb290IENBMB4XDTIx
MDcwMjIwNTUxNVoXDTMxMDYzMDIwNTUxNVowZDEoMCYGA1UEChMfU21hbGxzdGVw
IENlcnRpZmljYXRlIEF1dGhvcml0eTE4MDYGA1UEAxMvU21hbGxzdGVwIENlcnRp
ZmljYXRlIEF1dGhvcml0eSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAASyIaRXzoQAh/3KAXsPiPT9F4GSZjx6d196YQcOHDpwnAgQK673
qZRMC66JxKLbOktOU5x4h8w/FQZrJgaJr2Y2o2YwZDAOBgNVHQ8BAf8EBAMCAQYw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUyvJiytg7SAdKLV74gHr3sb+6
wu4wHwYDVR0jBBgwFoAUDAUw3LkOq/lk4wyu8MT8/KzC+JUwCgYIKoZIzj0EAwID
SAAwRQIgajYwweI1RXGxL5fAzYTJ/RdkmJ2AyXDuR4yZ9iMKAPgCIQCtuaOcL5Lr
/bHTNp86fL/DNLUkVN4hb8GGb0a4ahcWtA==
-----END CERTIFICATE-----
`), []byte(`
-----BEGIN CERTIFICATE-----
MIIB/TCCAaKgAwIBAgIRAMOGyeMi8guIr3cmDGnbGQ4wCgYIKoZIzj0EAwIwXDEo
MCYGA1UEChMfU21hbGxzdGVwIENlcnRpZmljYXRlIEF1dGhvcml0eTEwMC4GA1UE
AxMnU21hbGxzdGVwIENlcnRpZmljYXRlIEF1dGhvcml0eSBSb290IENBMB4XDTIx
MDcwMjIwNTUxM1oXDTMxMDYzMDIwNTUxM1owXDEoMCYGA1UEChMfU21hbGxzdGVw
IENlcnRpZmljYXRlIEF1dGhvcml0eTEwMC4GA1UEAxMnU21hbGxzdGVwIENlcnRp
ZmljYXRlIEF1dGhvcml0eSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEAo4lg5M4cjKljjdBFu9X8e1Y9YCdaKdODQcoa3FaSgiFN3mF7WJPuKIcpqIP
F88j6b96CCiZqzr7MeZV6UqtgKNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB
/wQIMAYBAf8CAQEwHQYDVR0OBBYEFAwFMNy5Dqv5ZOMMrvDE/PyswviVMAoGCCqG
SM49BAMCA0kAMEYCIQCmWQcc69OTtL4w10F4fG5JaR4UFKh1rUIQpEKFW98d7QIh
AOspoifFYQGC5zPbwFNoj/CZxcnVE3Fz3a/KKX+lerGN
-----END CERTIFICATE-----
`),
}

func parseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	parsed, _ := pem.Decode(pemBytes)
	if parsed == nil {
		return nil, fmt.Errorf("could not parse pem block")
	}
	return x509.ParseCertificate(parsed.Bytes)
}

func parseCABundle(bundle [][]byte) (x509.VerifyOptions, error) {
	options := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		Roots:         x509.NewCertPool(),
	}

	for _, certBytes := range bundle {
		parsed, _ := pem.Decode(certBytes)
		certificate, err := x509.ParseCertificate(parsed.Bytes)
		if err != nil {
			return x509.VerifyOptions{}, err
		}
		if bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
			options.Roots.AddCert(certificate)
		} else {
			options.Intermediates.AddCert(certificate)
		}
	}

	return options, nil
}

func TestVerifyAttestation(t *testing.T) {
	signedCertificate, err := parseCertificate(signedAttestationCertificateBytes)
	if err != nil {
		t.Fatalf("could not parse attested certificate %s", err)
	}
	signingCertificate, err := parseCertificate(attestationSigningCertificateBytes)
	if err != nil {
		t.Fatalf("could not parse attestation certificate %s", err)
	}
	chains, err := VerifyAttestation(signingCertificate, signedCertificate)
	if err != nil {
		t.Fatalf("could not verify attested certificate %s", err)
	}
	if len(chains) == 0 {
		t.Fatalf("expected at least one verified chain to be returned")
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

func TestVerifyAttestationWithOptions(t *testing.T) {
	options, err := parseCABundle(customCABytes)
	if err != nil {
		t.Fatalf("could not parse attestation chain %s", err)
	}
	signedCertificate, err := parseCertificate(customSignedAttestationCertificateBytes)
	if err != nil {
		t.Fatalf("could not parse attested certificate %s", err)
	}
	signingCertificate, err := parseCertificate(customAttestationSigningCertificateBytes)
	if err != nil {
		t.Fatalf("could not parse attestation certificate %s", err)
	}
	options.CurrentTime = signedCertificate.NotBefore.Add(1 * time.Second)
	chains, err := VerifyAttestationWithOptions(signingCertificate, signedCertificate, options)
	if err != nil {
		t.Fatalf("could not verify attested certificate %s", err)
	}
	if len(chains) == 0 {
		t.Fatalf("expected at least one verified chain to be returned")
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
