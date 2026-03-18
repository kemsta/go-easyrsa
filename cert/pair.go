package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
)

// CertType describes the role of a certificate.
type CertType string

const (
	CertTypeCA           CertType = "ca"
	CertTypeServer       CertType = "server"
	CertTypeClient       CertType = "client"
	CertTypeServerClient CertType = "serverClient"
)

// RevocationReason is an RFC 5280 revocation reason code.
type RevocationReason int

const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
)

// Pair holds a certificate and optionally its private key.
// KeyPEM may be nil in cert-only scenarios (e.g. after signing an external CSR).
type Pair struct {
	Name    string // storage key — the entity name, may differ from CN in org mode
	KeyPEM  []byte // nil if key is not held locally
	CertPEM []byte
}

// Certificate parses and returns the x509.Certificate from CertPEM.
func (p *Pair) Certificate() (*x509.Certificate, error) {
	block, _ := pem.Decode(p.CertPEM)
	if block == nil {
		return nil, errors.New("cert: failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// PrivateKey parses KeyPEM using PKCS8, supporting RSA, ECDSA, and Ed25519.
// Returns an error if KeyPEM is nil.
func (p *Pair) PrivateKey() (crypto.PrivateKey, error) {
	if p.KeyPEM == nil {
		return nil, errors.New("cert: no private key available")
	}
	block, _ := pem.Decode(p.KeyPEM)
	if block == nil {
		return nil, errors.New("cert: failed to decode key PEM block")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// Serial returns the certificate serial number.
func (p *Pair) Serial() (*big.Int, error) {
	cert, err := p.Certificate()
	if err != nil {
		return nil, err
	}
	return cert.SerialNumber, nil
}

// CertType derives the certificate type from extensions:
//
//	BasicConstraints.IsCA                           → CertTypeCA
//	ExtKeyUsageServerAuth only                      → CertTypeServer
//	ExtKeyUsageClientAuth only                      → CertTypeClient
//	ExtKeyUsageServerAuth + ExtKeyUsageClientAuth   → CertTypeServerClient
func (p *Pair) CertType() (CertType, error) {
	cert, err := p.Certificate()
	if err != nil {
		return "", err
	}
	if cert.IsCA {
		return CertTypeCA, nil
	}
	var hasServer, hasClient bool
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServer = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
	}
	switch {
	case hasServer && hasClient:
		return CertTypeServerClient, nil
	case hasServer:
		return CertTypeServer, nil
	case hasClient:
		return CertTypeClient, nil
	default:
		return CertTypeClient, nil
	}
}

// IsCA returns true if the certificate has the CA basic constraint.
func (p *Pair) IsCA() (bool, error) {
	cert, err := p.Certificate()
	if err != nil {
		return false, err
	}
	return cert.IsCA, nil
}

// HasKey reports whether a private key is stored locally.
func (p *Pair) HasKey() bool {
	return p.KeyPEM != nil
}
