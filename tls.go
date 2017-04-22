package ykpiv

import (
	"crypto/tls"
)

func (slot Slot) TLSCertificate() (*tls.Certificate, error) {
	cert, err := slot.Certificate()
	if err != nil {
		return nil, err
	}
	tlsCertificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  slot,
		Leaf:        cert,
	}
	return &tlsCertificate, nil
}
