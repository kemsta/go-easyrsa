package pki

import (
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/crypto"
	"github.com/kemsta/go-easyrsa/storage"
)

// BuildClientFull generates a client key and issues a signed client certificate.
func (p *PKI) BuildClientFull(name string, opts ...Option) (*cert.Pair, error) {
	if _, err := p.GenReq(name, opts...); err != nil {
		return nil, err
	}
	return p.SignReq(name, cert.CertTypeClient, opts...)
}

// BuildServerFull generates a server key and issues a signed server certificate.
func (p *PKI) BuildServerFull(name string, opts ...Option) (*cert.Pair, error) {
	if _, err := p.GenReq(name, opts...); err != nil {
		return nil, err
	}
	return p.SignReq(name, cert.CertTypeServer, opts...)
}

// BuildServerClientFull generates a key and issues a combined server+client certificate.
func (p *PKI) BuildServerClientFull(name string, opts ...Option) (*cert.Pair, error) {
	if _, err := p.GenReq(name, opts...); err != nil {
		return nil, err
	}
	return p.SignReq(name, cert.CertTypeServerClient, opts...)
}

// Renew renews a certificate by name, retaining the existing private key.
func (p *PKI) Renew(name string, opts ...Option) (*cert.Pair, error) {
	o := applyOptions(opts)

	existing, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	oldCert, err := existing.Certificate()
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

	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        oldCert.Subject,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       oldCert.KeyUsage,
		ExtKeyUsage:    oldCert.ExtKeyUsage,
		SubjectKeyId:   oldCert.SubjectKeyId,
		AuthorityKeyId: caCert.SubjectKeyId,
	}

	for _, mod := range o.certModifiers {
		mod(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, oldCert.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pemEncodeCert(certDER)

	pair := &cert.Pair{Name: name, CertPEM: certPEM, KeyPEM: existing.KeyPEM}
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

// ExpireCert forces a certificate into expired state in the index.
func (p *PKI) ExpireCert(name string) error {
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	serial, err := pair.Serial()
	if err != nil {
		return err
	}
	return p.index.Update(serial, storage.StatusExpired, time.Time{}, 0)
}
