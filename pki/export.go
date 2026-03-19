package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/kemsta/go-easyrsa/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/crypto"
)

// ExportP12 exports the named certificate and key as a PKCS#12 bundle.
func (p *PKI) ExportP12(name string, password string) ([]byte, error) {
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	privKey, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, p.config.KeyPassphrase)
	if err != nil {
		return nil, err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return nil, err
	}

	caPair, err := p.storage.GetLastByName(p.config.CAName)
	if err != nil {
		return nil, err
	}
	caCert, err := caPair.Certificate()
	if err != nil {
		return nil, err
	}

	return gopkcs12.Legacy.Encode(privKey, certificate, []*x509.Certificate{caCert}, password)
}

// ExportP7 exports the named certificate chain as a PKCS#7 bundle (no private key).
func (p *PKI) ExportP7(name string) ([]byte, error) {
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return nil, err
	}

	caPair, err := p.storage.GetLastByName(p.config.CAName)
	if err != nil {
		return nil, err
	}
	caCert, err := caPair.Certificate()
	if err != nil {
		return nil, err
	}

	sd, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}
	sd.AddCertificate(certificate)
	sd.AddCertificate(caCert)
	sd.Detach()

	der, err := sd.Finish()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der}), nil
}

// ExportP8 exports the named private key as a PKCS#8 PEM.
// If password is non-empty, the key is encrypted.
func (p *PKI) ExportP8(name string, password string) ([]byte, error) {
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	privKey, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, p.config.KeyPassphrase)
	if err != nil {
		return nil, err
	}
	return pkicrypto.MarshalPrivateKey(privKey, password)
}

// ExportP1 exports the named private key as a PKCS#1 PEM (RSA only).
func (p *PKI) ExportP1(name string) ([]byte, error) {
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return nil, err
	}
	privKey, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, p.config.KeyPassphrase)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: ExportP1 requires an RSA private key")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	}), nil
}

// GenDH generates Diffie-Hellman parameters of the given bit size.
func (p *PKI) GenDH(bits int) ([]byte, error) {
	return pkicrypto.GenDHParams(bits)
}

// SetPass changes the passphrase on the named private key.
func (p *PKI) SetPass(name string, oldPass, newPass string) error {
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	privKey, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, oldPass)
	if err != nil {
		return err
	}
	newKeyPEM, err := pkicrypto.MarshalPrivateKey(privKey, newPass)
	if err != nil {
		return err
	}
	updated := &cert.Pair{Name: pair.Name, CertPEM: pair.CertPEM, KeyPEM: newKeyPEM}
	return p.storage.Put(updated)
}
