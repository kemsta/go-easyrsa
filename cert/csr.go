package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
)

// CSR wraps a PEM-encoded certificate signing request.
type CSR struct {
	Name   string
	CSRPEM []byte
}

// Request parses and returns the x509.CertificateRequest from CSRPEM.
func (c *CSR) Request() (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(c.CSRPEM)
	if block == nil {
		return nil, errors.New("cert: failed to decode CSR PEM block")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// Subject returns the subject distinguished name from the CSR.
func (c *CSR) Subject() (pkix.Name, error) {
	req, err := c.Request()
	if err != nil {
		return pkix.Name{}, err
	}
	return req.Subject, nil
}
