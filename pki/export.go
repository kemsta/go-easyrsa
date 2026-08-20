package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path"

	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/kemsta/go-easyrsa/v2/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// ExportP12Options controls PKCS#12 membership and encoding compatibility.
type ExportP12Options struct {
	Password string
	NoCA     bool
	NoKey    bool
	Legacy   bool
}

// ExportP7Options controls PKCS#7 certificate membership.
type ExportP7Options struct {
	NoCA bool
}

// ExportP12 exports the named certificate as a PKCS#12 bundle, persists it at
// private/NAME.p12, and returns the exact persisted bytes.
func (p *PKI) ExportP12(name string, options ExportP12Options) ([]byte, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) ([]byte, error) { return bound.ExportP12(name, options) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return nil, err
	}

	encoder := gopkcs12.Modern
	switch {
	case options.Legacy:
		encoder = gopkcs12.Legacy
	case options.Password == "":
		encoder = gopkcs12.Passwordless
	}

	var caCertificates []*x509.Certificate
	if !options.NoCA {
		caPair, err := p.storage.GetLastByName(p.config.CAName)
		if err != nil {
			return nil, err
		}
		caCertificate, err := caPair.Certificate()
		if err != nil {
			return nil, err
		}
		caCertificates = append(caCertificates, caCertificate)
	}

	var data []byte
	if options.NoKey {
		certificates := append([]*x509.Certificate{certificate}, caCertificates...)
		data, err = encoder.EncodeTrustStore(certificates, options.Password)
	} else {
		privateKey, keyErr := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, p.keyInputPassphrase(name))
		if keyErr != nil {
			return nil, keyErr
		}
		data, err = encoder.Encode(privateKey, certificate, caCertificates, options.Password)
	}
	if err != nil {
		return nil, err
	}
	if err := p.artifacts.PutArtifact(storage.Artifact{
		Path:       path.Join("private", name+".p12"),
		Data:       data,
		Visibility: storage.ArtifactPrivate,
	}); err != nil {
		return nil, err
	}
	return data, nil
}

// ExportP7 exports the named certificate chain as a PKCS#7 bundle, persists it
// at issued/NAME.p7b, and returns the exact persisted bytes.
func (p *PKI) ExportP7(name string, options ExportP7Options) ([]byte, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) ([]byte, error) { return bound.ExportP7(name, options) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return nil, err
	}

	signedData, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}
	signedData.AddCertificate(certificate)
	if !options.NoCA {
		caPair, err := p.storage.GetLastByName(p.config.CAName)
		if err != nil {
			return nil, err
		}
		caCertificate, err := caPair.Certificate()
		if err != nil {
			return nil, err
		}
		signedData.AddCertificate(caCertificate)
	}
	signedData.Detach()
	der, err := signedData.Finish()
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
	if err := p.artifacts.PutArtifact(storage.Artifact{
		Path:       path.Join("issued", name+".p7b"),
		Data:       data,
		Visibility: storage.ArtifactPublic,
	}); err != nil {
		return nil, err
	}
	return data, nil
}

// ExportP8 exports the named private key as PKCS#8, persists it at
// private/NAME.p8, and returns the exact persisted bytes. An empty password
// selects plaintext PKCS#8.
func (p *PKI) ExportP8(name, password string) ([]byte, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) ([]byte, error) { return bound.ExportP8(name, password) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	keyPEM, err := p.storage.GetPrivateKey(name)
	if err != nil {
		return nil, err
	}
	privateKey, err := pkicrypto.UnmarshalPrivateKey(keyPEM, p.keyInputPassphrase(name))
	if err != nil {
		return nil, err
	}
	data, err := pkicrypto.MarshalPrivateKey(privateKey, password)
	if err != nil {
		return nil, err
	}
	if err := p.artifacts.PutArtifact(storage.Artifact{
		Path:       path.Join("private", name+".p8"),
		Data:       data,
		Visibility: storage.ArtifactPrivate,
	}); err != nil {
		return nil, err
	}
	return data, nil
}

// ExportP1 exports an RSA private key as PKCS#1, persists it at
// private/NAME.p1, and returns the exact persisted bytes. An empty password
// selects plaintext legacy PEM.
func (p *PKI) ExportP1(name, password string) ([]byte, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) ([]byte, error) { return bound.ExportP1(name, password) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	keyPEM, err := p.storage.GetPrivateKey(name)
	if err != nil {
		return nil, err
	}
	privateKey, err := pkicrypto.UnmarshalPrivateKey(keyPEM, p.keyInputPassphrase(name))
	if err != nil {
		return nil, err
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: ExportP1 requires an RSA private key")
	}
	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	var data []byte
	if password == "" {
		data = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	} else {
		block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte(password), x509.PEMCipherAES256) //nolint:staticcheck // Easy-RSA compatibility requires legacy PEM encryption.
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(block)
	}
	if err := p.artifacts.PutArtifact(storage.Artifact{
		Path:       path.Join("private", name+".p1"),
		Data:       data,
		Visibility: storage.ArtifactPrivate,
	}); err != nil {
		return nil, err
	}
	return data, nil
}

// GenDH generates Diffie-Hellman parameters, persists them at dh.pem, and
// returns the exact persisted bytes.
func (p *PKI) GenDH(bits int) ([]byte, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) ([]byte, error) { return bound.GenDH(bits) })
	}
	data, err := pkicrypto.GenDHParams(bits)
	if err != nil {
		return nil, err
	}
	if err := p.artifacts.PutArtifact(storage.Artifact{
		Path:       "dh.pem",
		Data:       data,
		Visibility: storage.ArtifactPublic,
	}); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *PKI) keyInputPassphrase(name string) string {
	if name == p.config.CAName {
		return p.config.CAPassphrase
	}
	return p.config.KeyPassphrase
}

// SetPass changes the passphrase on the named private key.
func (p *PKI) SetPass(name string, oldPass, newPass string) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.SetPass(name, oldPass, newPass) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	privateKey, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, oldPass)
	if err != nil {
		return err
	}
	newKeyPEM, err := pkicrypto.MarshalPrivateKey(privateKey, newPass)
	if err != nil {
		return err
	}
	updated := &cert.Pair{Name: pair.Name, CertPEM: pair.CertPEM, KeyPEM: newKeyPEM}
	return p.storage.Put(updated)
}
