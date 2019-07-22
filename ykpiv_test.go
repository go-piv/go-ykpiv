/* {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2017
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. }}} */

package ykpiv_test

import (
	"bytes"
	"crypto"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"encoding/asn1"

	"math/big"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"pault.ag/go/ykpiv"
)

func isok(t *testing.T, err error) {
	t.Helper()
	if err != nil && err != io.EOF {
		t.Fatalf("Error! Error is not nil! %s", err)
	}
}

func notok(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.FailNow()
		t.Fatal("Error! Error is nil!")
	}
}

func assert(t *testing.T, expr bool, what string) {
	t.Helper()
	if !expr {
		t.Fatalf("Assertion failed: %s", what)
	}
}

func isDestructive() {
	if os.Getenv("YKPIV_YES_DESTROY_MY_KEY") == "" {
		panic("export YKPIV_YES_DESTROY_MY_KEY=true # if you want to test this code on a Key")
	}

	if err := wipeYubikey(); err != nil {
		panic(err)
	}
}

func TestImportKey(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	isok(t, yubikey.Login())
	isok(t, yubikey.Authenticate())

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	isok(t, err)

	slot, err := yubikey.ImportKey(ykpiv.KeyManagement, privKey)
	isok(t, err)

	plaintext := []byte("Well ain't this dandy")

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &privKey.PublicKey, plaintext)
	isok(t, err)

	decrypted, err := slot.Decrypt(rand.Reader, encrypted, nil)
	isok(t, err)

	assert(t, bytes.Equal(plaintext, decrypted), "Plaintexts don't match")

	template := certificateTemplate()
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, slot.PublicKey, slot)
	isok(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	isok(t, err)

	err = slot.Update(*cert)
	isok(t, err)

	slot, err = yubikey.KeyManagement()
	isok(t, err)

	assert(t, slot.Certificate.Subject.CommonName == template.Subject.CommonName, "Certificate common names are doesn't match")

	hasher := sha512.New()
	_, err = hasher.Write(plaintext)
	isok(t, err)
	hashed := hasher.Sum(plaintext[:0])

	signature, err := slot.Sign(nil, hashed, crypto.SHA512)
	isok(t, err)

	err = rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA512, hashed, signature)
	isok(t, err)
}

func getYubikey(PIN, PUK string) (*ykpiv.Yubikey, func() error, error) {
	yk, err := ykpiv.New(ykpiv.Options{
		Reader:             yubikeyReaderName,
		PIN:                &PIN,
		PUK:                &PUK,
		ManagementKeyIsPIN: false,
		ManagementKey: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return yk, yk.Close, nil
}

func wipeYubikey() error {
	yubikey, closer, err := getYubikey("654321", "87654321")
	if err != nil {
		return err
	}
	defer closer()

	retries, err := yubikey.PINRetries()
	if err != nil {
		return err
	}
	for i := 0; i < retries; i++ {
		yubikey.Login()
	}

	retries, _ = yubikey.PINRetries()
	if retries != 0 {
		return fmt.Errorf("Error wiping Yubikey")
	}

	yubikey.ChangePUK("87654321")
	yubikey.ChangePUK("87654321")
	yubikey.ChangePUK("87654321")

	return yubikey.Reset()
}

var yubikeyReaderName = "Yubikey"
var defaultPIN = "123456"
var defaultPUK = "12345678"
var allSlots = []ykpiv.SlotId{
	ykpiv.Authentication,
	ykpiv.Signature,
	ykpiv.KeyManagement,
	ykpiv.CardAuthentication,
}

func TestReader(t *testing.T) {
	readers, err := ykpiv.Readers()
	isok(t, err)
	assert(t, len(readers) != 0, "No readers found")
}

func certificateTemplate() x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24)

	return x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "p̶͕͉̟ͅḁ̲̳̕u̪̬̯̗͎͡l̷͍͎̤̠t̥̗͞ag",
			Organization: []string{"go-ykpiv"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}
}

func TestUpdate(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	isok(t, yubikey.Login())
	isok(t, yubikey.Authenticate())

	slotFunc := map[ykpiv.SlotId]func() (*ykpiv.Slot, error){
		ykpiv.Authentication:     yubikey.Authentication,
		ykpiv.Signature:          yubikey.Signature,
		ykpiv.KeyManagement:      yubikey.KeyManagement,
		ykpiv.CardAuthentication: yubikey.CardAuthentication,
	}

	for _, slotId := range allSlots {

		slot, err := yubikey.GenerateRSA(slotId, 1024)
		isok(t, err)

		// When using "Digital Signature" slot, PIN must be provided every time.
		if slot.Id == ykpiv.Signature {
			isok(t, yubikey.Login())
		}

		template := certificateTemplate()
		derCertificate, err := x509.CreateCertificate(rand.Reader, &template, &template, slot.PublicKey, slot)
		isok(t, err)
		certificate, err := x509.ParseCertificate(derCertificate)
		isok(t, err)
		isok(t, slot.Update(*certificate))
		slot1, err := slotFunc[slot.Id]()
		isok(t, err)
		assert(
			t,
			slot1.Certificate.Subject.CommonName == template.Subject.CommonName,
			"Common Name is wrong",
		)

		// Now, let's assert it's not what we're going to check next.
		assert(
			t,
			slot1.Certificate.Subject.CommonName != "paultag",
			"Common Name is wrong",
		)

		if slot.Id == ykpiv.Signature {
			isok(t, yubikey.Login())
		}

		template.Subject.CommonName = "paultag"
		derCertificate, err = x509.CreateCertificate(rand.Reader, &template, &template, slot.PublicKey, slot)
		isok(t, err)
		certificate, err = x509.ParseCertificate(derCertificate)
		isok(t, err)
		isok(t, slot.Update(*certificate))
		slot2, err := slotFunc[slot.Id]()
		isok(t, err)
		assert(
			t,
			slot2.Certificate.Subject.CommonName == "paultag",
			"Common Name is wrong",
		)
	}
}

func TestGenerateRSAEncryption(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	isok(t, yubikey.Login())
	isok(t, yubikey.Authenticate())

	slot, err := yubikey.GenerateRSA(ykpiv.Authentication, 1024)
	isok(t, err)
	assert(t, slot.PublicKey.(*rsa.PublicKey).N.BitLen() == 1024, "BitLen is wrong")

	plaintext := []byte("Well ain't this dandy")

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, slot.PublicKey.(*rsa.PublicKey), plaintext)
	isok(t, err)

	computedPlaintext, err := slot.Decrypt(rand.Reader, ciphertext, nil)
	isok(t, err)

	assert(t, bytes.Compare(plaintext, computedPlaintext) == 0, "Plaintexts don't match")
}

func TestGenerateRSA1024(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	for _, slotId := range allSlots {
		isok(t, yubikey.Login())
		isok(t, yubikey.Authenticate())

		slot, err := yubikey.GenerateRSA(slotId, 1024)
		isok(t, err)
		assert(t, slot.PublicKey.(*rsa.PublicKey).N.BitLen() == 1024, "BitLen is wrong")
	}
}

func TestWriteSaveCycle(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	yubikey.Login()
	yubikey.Authenticate()
	isok(t, yubikey.SaveObject(0x5FCAFE, []byte("p̶͕͉̟ͅḁ̲̳̕u̪̬̯̗͎͡l̷͍͎̤̠t̥̗͞ag")))

	whoami, err := yubikey.GetObject(0x5FCAFE)
	isok(t, err)

	assert(t, bytes.Compare(whoami, []byte("p̶͕͉̟ͅḁ̲̳̕u̪̬̯̗͎͡l̷͍͎̤̠t̥̗͞ag")) == 0, "get object returns good data")
}

func TestGenerateRSA2048(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	for _, slotId := range allSlots {
		isok(t, yubikey.Login())
		isok(t, yubikey.Authenticate())

		slot, err := yubikey.GenerateRSA(slotId, 2048)
		isok(t, err)
		assert(t, slot.PublicKey.(*rsa.PublicKey).N.BitLen() == 2048, "BitLen is wrong")
	}
}

func TestSignEC(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	for _, bits := range []int{256, 384} {
		for _, slotId := range allSlots {
			for _, hf := range []struct {
				newh func() hash.Hash
				hash crypto.Hash
			}{
				{sha512.New, crypto.SHA512},
				{sha256.New, crypto.SHA256},
			} {

				isok(t, yubikey.Login())
				isok(t, yubikey.Authenticate())

				slot, err := yubikey.GenerateEC(slotId, bits)
				isok(t, err)

				h := hf.newh()
				_, err = h.Write([]byte("test"))
				isok(t, err)
				digest := h.Sum(nil)

				// When using "Digital Signature" slot, PIN must be provided every time.
				if slotId == ykpiv.Signature {
					isok(t, yubikey.Login())
				}

				sig, err := slot.Sign(nil, digest[:], hf.hash)
				isok(t, err)

				pubKey, ok := slot.PublicKey.(*ecdsa.PublicKey)
				assert(t, ok, "invalid public key type")

				R, S := decodeSig(t, sig)
				ok = ecdsa.Verify(pubKey, digest[:], R, S)
				assert(t, ok, "ECDSA verification failed")
			}
		}
	}
}

func TestTLSCertificate(t *testing.T) {
	isDestructive()

	yubikey, closer, err := getYubikey(defaultPIN, defaultPUK)
	isok(t, err)
	defer closer()

	isok(t, yubikey.Login())
	isok(t, yubikey.Authenticate())

	tmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "my-server"},
		SerialNumber: big.NewInt(1000),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"pipe"},
	}

	slot, err := yubikey.GenerateEC(ykpiv.Authentication, 256)
	isok(t, err)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, slot.PublicKey, slot)
	isok(t, err)

	cert, err := x509.ParseCertificate(certDER)
	isok(t, err)
	isok(t, slot.Update(*cert))

	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	c := tls.Client(clientConn, &tls.Config{ServerName: "pipe", RootCAs: certPool})
	s := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{slot.TLSCertificate()},
	})

	errc := make(chan error)
	go func() { errc <- c.Handshake() }()
	go func() { errc <- s.Handshake() }()
	isok(t, <-errc)
	isok(t, <-errc)
}

func decodeSig(t *testing.T, sig []byte) (R *big.Int, S *big.Int) {
	t.Helper()
	rawData := asn1.RawValue{}
	_, err := asn1.Unmarshal(sig, &rawData)
	isok(t, err)
	RB := asn1.RawValue{}
	rest, err := asn1.Unmarshal(rawData.Bytes, &RB)
	isok(t, err)
	assert(t, len(rest) != 0, "S missing")
	SB := asn1.RawValue{}
	rest, err = asn1.Unmarshal(rest, &SB)
	assert(t, len(rest) == 0, "unexpected extra data")
	R = new(big.Int)
	R.SetBytes(RB.Bytes)
	S = new(big.Int)
	S.SetBytes(SB.Bytes)
	return
}

func TestMain(m *testing.M) {
	isDestructive()

	os.Exit(m.Run())
}

// vim: foldmethod=marker
