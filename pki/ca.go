package pki

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/crypto"
	"github.com/kemsta/go-easyrsa/storage"
)

// ShowCA returns the CA certificate pair.
func (p *PKI) ShowCA() (*cert.Pair, error) {
	return p.storage.GetLastByName(p.config.CAName)
}

// BuildCA creates a new CA certificate and private key.
func (p *PKI) BuildCA(opts ...Option) (*cert.Pair, error) {
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
	pubKey, err := pkicrypto.PublicKey(privKey)
	if err != nil {
		return nil, err
	}

	cn := p.config.CAName
	if o.subject != nil && o.subject.CommonName != "" {
		cn = o.subject.CommonName
	}

	subject := buildSubject(p.config, o, cn)

	notBefore := time.Now()
	if !o.notBefore.IsZero() {
		notBefore = o.notBefore
	}
	notAfter := notBefore.AddDate(0, 0, p.config.CADays)
	if !o.notAfter.IsZero() {
		notAfter = o.notAfter
	}

	serial, err := p.nextSerial()
	if err != nil {
		return nil, err
	}

	skid, err := subjectKeyID(pubKey)
	if err != nil {
		return nil, err
	}

	pathLen := -1 // no constraint
	if o.subCAPathLen != nil {
		pathLen = *o.subCAPathLen
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
	}

	for _, mod := range o.certModifiers {
		mod(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := pemEncodeCert(certDER)
	passphrase, err := p.keyPassphrase(o)
	if err != nil {
		return nil, err
	}
	keyPEM, err := pkicrypto.MarshalPrivateKey(privKey, passphrase)
	if err != nil {
		return nil, err
	}

	pair := &cert.Pair{
		Name:    p.config.CAName,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
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

// RenewCA renews the CA certificate, retaining the existing private key.
func (p *PKI) RenewCA(opts ...Option) (*cert.Pair, error) {
	o := applyOptions(opts)

	existing, err := p.storage.GetLastByName(p.config.CAName)
	if err != nil {
		return nil, err
	}

	privKey, err := pkicrypto.UnmarshalPrivateKey(existing.KeyPEM, p.config.CAPassphrase)
	if err != nil {
		return nil, err
	}
	pubKey, err := pkicrypto.PublicKey(privKey)
	if err != nil {
		return nil, err
	}

	oldCert, err := existing.Certificate()
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	if !o.notBefore.IsZero() {
		notBefore = o.notBefore
	}
	notAfter := notBefore.AddDate(0, 0, p.config.CADays)
	if !o.notAfter.IsZero() {
		notAfter = o.notAfter
	}

	serial, err := p.nextSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               oldCert.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              oldCert.KeyUsage,
		SubjectKeyId:          oldCert.SubjectKeyId,
		AuthorityKeyId:        oldCert.SubjectKeyId,
	}

	for _, mod := range o.certModifiers {
		mod(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := pemEncodeCert(certDER)
	keyPEM := existing.KeyPEM
	if o.passphrase != "" || (o.noPass != nil && *o.noPass) {
		var passphrase string
		passphrase, err = p.keyPassphrase(o)
		if err != nil {
			return nil, err
		}
		keyPEM, err = pkicrypto.MarshalPrivateKey(privKey, passphrase)
		if err != nil {
			return nil, err
		}
	}

	pair := &cert.Pair{
		Name:    p.config.CAName,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
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

// nextSerial returns the next serial number.
// If RandomSerial is configured, returns a random 128-bit integer.
// Otherwise uses the SerialProvider.
func (p *PKI) nextSerial() (*big.Int, error) {
	if p.config.RandomSerial {
		return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return p.serial.Next()
}

// buildSubject constructs a pkix.Name from config defaults and option overrides.
// In DNModeCNOnly (default), only CommonName is set; SubjTemplate org fields are ignored.
// In DNModeOrg, all SubjTemplate fields are included and can be overridden by options.
func buildSubject(cfg Config, o options, cn string) pkix.Name {
	if cfg.DNMode == DNModeCNOnly || cfg.DNMode == "" {
		name := pkix.Name{CommonName: cn}
		if o.subject != nil && o.subject.CommonName != "" {
			name.CommonName = o.subject.CommonName
		}
		if o.subjectSerial != "" {
			name.SerialNumber = o.subjectSerial
		}
		return name
	}

	// org mode: include all fields from SubjTemplate, override with options.
	name := cfg.SubjTemplate
	name.CommonName = cn
	if o.subject != nil {
		if o.subject.CommonName != "" {
			name.CommonName = o.subject.CommonName
		}
		if len(o.subject.Organization) > 0 {
			name.Organization = o.subject.Organization
		}
		if len(o.subject.Country) > 0 {
			name.Country = o.subject.Country
		}
		if len(o.subject.Province) > 0 {
			name.Province = o.subject.Province
		}
		if len(o.subject.Locality) > 0 {
			name.Locality = o.subject.Locality
		}
		if len(o.subject.OrganizationalUnit) > 0 {
			name.OrganizationalUnit = o.subject.OrganizationalUnit
		}
	}
	if o.subjectSerial != "" {
		name.SerialNumber = o.subjectSerial
	}
	return name
}

// subjectKeyID computes the Subject Key Identifier (SHA-1 of public key DER).
func subjectKeyID(pub interface{}) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// SubjectPublicKeyInfo is SEQUENCE { SEQUENCE { OID, params }, BIT STRING key }
	// We hash just the BIT STRING content (the actual key bytes).
	var spki struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		// fallback: hash entire DER
		h := sha1.Sum(der) //nolint:gosec // SHA-1 required by RFC 5280 for SKID
		return h[:], nil
	}
	h := sha1.Sum(spki.SubjectPublicKey.Bytes) //nolint:gosec // SHA-1 required by RFC 5280 for SKID
	return h[:], nil
}
