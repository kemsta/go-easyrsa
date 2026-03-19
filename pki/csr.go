package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/crypto"
	"github.com/kemsta/go-easyrsa/storage"
)

// GenReq generates a private key and a Certificate Signing Request.
// The CSR PEM is returned and also stored via CSRStorage.
// The key is stored in KeyStorage (cert-less pair).
func (p *PKI) GenReq(name string, opts ...Option) (csrPEM []byte, err error) {
	o := applyOptions(opts)

	algo := string(p.config.KeyAlgo)
	if o.keyAlgo != "" {
		algo = string(o.keyAlgo)
	}
	keySize := p.config.KeySize
	if o.keySize != 0 {
		keySize = o.keySize
	}
	curve := p.config.Curve
	if o.curve != nil {
		curve = o.curve
	}

	privKey, err := pkicrypto.GenKey(algo, keySize, curve)
	if err != nil {
		return nil, err
	}

	cn := name
	if o.subject != nil && o.subject.CommonName != "" {
		cn = o.subject.CommonName
	}
	subject := buildSubject(p.config, o, cn)

	template := &x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       o.dnsNames,
		IPAddresses:    o.ipAddresses,
		EmailAddresses: o.emailAddrs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, err
	}
	csrPEM = pemEncodeCSR(csrDER)

	passphrase, err := p.keyPassphrase(o)
	if err != nil {
		return nil, err
	}
	keyPEM, err := pkicrypto.MarshalPrivateKey(privKey, passphrase)
	if err != nil {
		return nil, err
	}

	// Store the key (cert-less pair — cert will come after SignReq)
	if err := p.storage.Put(&cert.Pair{Name: name, KeyPEM: keyPEM}); err != nil {
		return nil, err
	}

	if err := p.csrStorage.PutCSR(name, csrPEM); err != nil {
		return nil, err
	}

	return csrPEM, nil
}

// ImportReq stores an externally generated CSR under the given name.
func (p *PKI) ImportReq(name string, csrPEM []byte) error {
	// Validate the CSR before storing.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return errors.New("pki: failed to decode CSR PEM")
	}
	if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
		return err
	}
	return p.csrStorage.PutCSR(name, csrPEM)
}

// SignReq signs a stored CSR and returns the resulting certificate pair.
func (p *PKI) SignReq(name string, certType cert.CertType, opts ...Option) (*cert.Pair, error) {
	o := applyOptions(opts)

	csrPEM, err := p.csrStorage.GetCSR(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("pki: failed to decode stored CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	caPair, err := p.storage.GetLastByName(p.config.CAName)
	if err != nil {
		return nil, err
	}
	caKey, err := pkicrypto.UnmarshalPrivateKey(caPair.KeyPEM, p.config.CAPassphrase)
	if err != nil {
		return nil, err
	}
	caCert, err := caPair.Certificate()
	if err != nil {
		return nil, err
	}

	serial, err := p.nextSerial()
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	if !o.notBefore.IsZero() {
		notBefore = o.notBefore
	}
	notAfter := notBefore.AddDate(0, 0, p.config.DefaultDays)
	if !o.notAfter.IsZero() {
		notAfter = o.notAfter
	}

	subject := csr.Subject
	if o.subjectOverride != nil {
		subject = *o.subjectOverride
	}

	skid, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        subject,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		SubjectKeyId:   skid,
		AuthorityKeyId: caCert.SubjectKeyId,
	}

	// Apply cert type specific extensions.
	switch certType {
	case cert.CertTypeCA:
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if o.subCAPathLen != nil {
			template.MaxPathLen = *o.subCAPathLen
			template.MaxPathLenZero = *o.subCAPathLen == 0
		}
	case cert.CertTypeServer:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case cert.CertTypeServerClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default: // CertTypeClient
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Copy SANs from CSR if requested.
	if o.copyCSRExtensions {
		template.DNSNames = csr.DNSNames
		template.IPAddresses = csr.IPAddresses
		template.EmailAddresses = csr.EmailAddresses
	}
	// Option-supplied SANs override/extend.
	if len(o.dnsNames) > 0 {
		template.DNSNames = o.dnsNames
	}
	if len(o.ipAddresses) > 0 {
		template.IPAddresses = o.ipAddresses
	}
	if len(o.emailAddrs) > 0 {
		template.EmailAddresses = o.emailAddrs
	}

	for _, mod := range o.certModifiers {
		mod(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pemEncodeCert(certDER)

	// Retrieve existing key if present (from GenReq).
	var keyPEM []byte
	if existing, err := p.storage.GetLastByName(name); err == nil {
		keyPEM = existing.KeyPEM
	}

	pair := &cert.Pair{Name: name, CertPEM: certPEM, KeyPEM: keyPEM}
	if err := p.storage.Put(pair); err != nil {
		return nil, err
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	if err := p.index.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		ExpiresAt: parsedCert.NotAfter,
		Serial:    parsedCert.SerialNumber,
		Subject:   parsedCert.Subject,
	}); err != nil {
		return nil, err
	}

	return pair, nil
}

