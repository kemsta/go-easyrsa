package pair

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

const (
	PEMCertificateBlock   string = "CERTIFICATE"     // pem block header for x509.Certificate
	PEMRSAPrivateKeyBlock        = "RSA PRIVATE KEY" // pem block header for rsa.PrivateKey
)

// X509Pair represent pair cert and key
type X509Pair struct {
	keyPemBytes  []byte   // pem encoded rsa.PrivateKey bytes
	certPemBytes []byte   // pem encoded x509.Certificate bytes
	cn           string   // common name
	serial       *big.Int // serial number
}

func (pair *X509Pair) KeyPemBytes() []byte {
	return pair.keyPemBytes
}

func (pair *X509Pair) CertPemBytes() []byte {
	return pair.certPemBytes
}

func (pair *X509Pair) CN() string {
	return pair.cn
}

func (pair *X509Pair) Serial() *big.Int {
	return pair.serial
}

// Decode pem bytes to rsa.PrivateKey and x509.Certificate
func (pair *X509Pair) Decode() (key *rsa.PrivateKey, cert *x509.Certificate, err error) {
	block, _ := pem.Decode(pair.keyPemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("can`t parse key: %v", string(pair.keyPemBytes))
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("can`t parse key %v: %w", string(block.Bytes), err)
	}

	block, _ = pem.Decode(pair.certPemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("can`t parse cert: %v", string(pair.certPemBytes))
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("can`t parse cert %v: %w", string(block.Bytes), err)
	}
	return
}

// NewX509Pair create new X509Pair object
func NewX509Pair(key *rsa.PrivateKey, cert *x509.Certificate) *X509Pair {

	return &X509Pair{keyPemBytes: pem.EncodeToMemory(&pem.Block{
		Type:  PEMRSAPrivateKeyBlock,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), certPemBytes: pem.EncodeToMemory(&pem.Block{
		Type:  PEMCertificateBlock,
		Bytes: cert.Raw,
	}),
		cn:     cert.Subject.CommonName,
		serial: cert.SerialNumber}
}

func ImportX509(keyPemBytes []byte, certPemBytes []byte, CN string, serial *big.Int) *X509Pair {
	return &X509Pair{keyPemBytes: keyPemBytes, certPemBytes: certPemBytes, cn: CN, serial: serial}
}
