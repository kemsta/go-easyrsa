package pair

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// X509Pair represent pair cert and key
type X509Pair struct {
	KeyPemBytes  []byte   // pem encoded rsa.PrivateKey bytes
	CertPemBytes []byte   // pem encoded x509.Certificate bytes
	CN           string   // common name
	Serial       *big.Int // serial number
}

// Decode pem bytes to rsa.PrivateKey and x509.Certificate
func (pair *X509Pair) Decode() (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	block, _ := pem.Decode(pair.KeyPemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("can`t parse key: %v", string(pair.KeyPemBytes))
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("can`t parse key %v: %w", string(block.Bytes), err)
	}

	block, _ = pem.Decode(pair.CertPemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("can`t parse cert: %v", string(pair.CertPemBytes))
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("can`t parse cert %v: %w", string(block.Bytes), err)
	}
	return
}

// NewX509Pair create new X509Pair object
func NewX509Pair(keyPemBytes []byte, certPemBytes []byte, CN string, serial *big.Int) *X509Pair {
	return &X509Pair{KeyPemBytes: keyPemBytes, CertPemBytes: certPemBytes, CN: CN, Serial: serial}
}
