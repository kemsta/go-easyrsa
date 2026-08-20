package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// GenReq generates a private key and a Certificate Signing Request.
// The CSR PEM is returned and also stored via CSRStorage.
// The key is stored in KeyStorage (cert-less pair).
func (p *PKI) GenReq(name string, opts ...Option) (csrPEM []byte, err error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) ([]byte, error) { return bound.GenReq(name, opts...) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
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
	// Easy-RSA's default digest is SHA-256 for every ECDSA curve. Go's x509
	// default scales the digest with the curve, so select SHA-256 explicitly.
	if _, ok := privKey.(*ecdsa.PrivateKey); ok {
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
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
		// Best-effort cleanup: remove the orphaned key so storage is not left
		// with a key-only pair that has no corresponding CSR or certificate.
		_ = p.storage.DeleteByName(name)
		return nil, err
	}

	return csrPEM, nil
}

// ImportReq stores an externally generated CSR under the given name.
func (p *PKI) ImportReq(name string, csrPEM []byte) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.ImportReq(name, csrPEM) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
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
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) (*cert.Pair, error) {
			return bound.SignReq(name, certType, opts...)
		})
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
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
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature verification failed: %w", err)
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
	notAfter := addExactDays(notBefore, p.config.DefaultDays)
	if !o.notAfter.IsZero() {
		notAfter = o.notAfter
	}

	subject := csr.Subject
	rawSubject := append([]byte(nil), csr.RawSubject...)
	if o.subjectOverride != nil {
		subject = *o.subjectOverride
		rawSubject = nil
	}

	skid, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        subject,
		RawSubject:     rawSubject,
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
	case cert.CertTypeClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("pki: unknown cert type %q", certType)
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
	if len(o.certificateDNSNames) > 0 {
		template.DNSNames = o.certificateDNSNames
	}
	if len(o.certificateIPs) > 0 {
		template.IPAddresses = o.certificateIPs
	}
	if len(o.certificateEmails) > 0 {
		template.EmailAddresses = o.certificateEmails
	}

	subjectBeforeModifiers := cloneName(template.Subject)
	rawSubjectBeforeModifiers := append([]byte(nil), template.RawSubject...)
	for _, mod := range o.certModifiers {
		mod(template)
	}
	if !reflect.DeepEqual(template.Subject, subjectBeforeModifiers) && bytes.Equal(template.RawSubject, rawSubjectBeforeModifiers) {
		template.RawSubject = nil
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pemEncodeCert(certDER)

	// Parse the cert to get index fields.
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Retrieve the pending/current private key if present (from GenReq).
	var keyPEM []byte
	if existingKey, err := p.storage.GetPrivateKey(name); err == nil {
		keyPEM = existingKey
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}

	pair := &cert.Pair{Name: name, CertPEM: certPEM, KeyPEM: keyPEM}
	if err := p.storage.Put(pair); err != nil {
		return nil, err
	}
	if err := p.index.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		ExpiresAt: parsedCert.NotAfter,
		Serial:    parsedCert.SerialNumber,
		Subject:   parsedCert.Subject,
	}); err != nil {
		_ = p.storage.DeleteByName(name)
		return nil, err
	}

	return pair, nil
}
