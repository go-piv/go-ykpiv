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
	"io"
	"log"
	"os"
	"testing"
	"time"

	"math/big"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"

	"pault.ag/go/ykpiv"
)

func isok(t *testing.T, err error) {
	if err != nil && err != io.EOF {
		log.Printf("Error! Error is not nil! %s\n", err)
		t.FailNow()
	}
}

func notok(t *testing.T, err error) {
	if err == nil {
		log.Printf("Error! Error is nil!\n")
		t.FailNow()
	}
}

func assert(t *testing.T, expr bool, what string) {
	if !expr {
		log.Printf("Assertion failed: %s", what)
		t.FailNow()
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

	slot, err := yubikey.GenerateRSA(ykpiv.Authentication, 1024)
	isok(t, err)

	template := certificateTemplate()
	derCertificate, err := x509.CreateCertificate(rand.Reader, &template, &template, slot.PublicKey, slot)
	isok(t, err)
	certificate, err := x509.ParseCertificate(derCertificate)
	isok(t, err)
	isok(t, slot.Update(*certificate))
	authentication, err := yubikey.Authentication()
	isok(t, err)
	assert(
		t,
		authentication.Certificate.Subject.CommonName == template.Subject.CommonName,
		"Common Name is wrong",
	)

	// Now, let's assert it's not what we're going to check next.
	assert(
		t,
		authentication.Certificate.Subject.CommonName != "paultag",
		"Common Name is wrong",
	)

	template.Subject.CommonName = "paultag"
	derCertificate, err = x509.CreateCertificate(rand.Reader, &template, &template, slot.PublicKey, slot)
	isok(t, err)
	certificate, err = x509.ParseCertificate(derCertificate)
	isok(t, err)
	isok(t, slot.Update(*certificate))
	authentication, err = yubikey.Authentication()
	isok(t, err)
	assert(
		t,
		authentication.Certificate.Subject.CommonName == "paultag",
		"Common Name is wrong",
	)
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

func TestMain(m *testing.M) {
	isDestructive()

	os.Exit(m.Run())
}

// vim: foldmethod=marker
