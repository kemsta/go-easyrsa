package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/crypto"
	"github.com/kemsta/go-easyrsa/storage"
)

// Revoke revokes all certificates stored under the given name.
func (p *PKI) Revoke(name string, reason cert.RevocationReason) error {
	pairs, err := p.storage.GetByName(name)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, pair := range pairs {
		if pair.CertPEM == nil {
			continue
		}
		serial, err := pair.Serial()
		if err != nil {
			continue
		}
		_ = p.index.Update(serial, storage.StatusRevoked, now, reason)
	}
	_, err = p.GenCRL()
	return err
}

// RevokeBySerial revokes the certificate identified by the given serial number.
func (p *PKI) RevokeBySerial(serial *big.Int, reason cert.RevocationReason) error {
	// Verify the cert exists.
	if _, err := p.storage.GetBySerial(serial); err != nil {
		return err
	}
	if err := p.index.Update(serial, storage.StatusRevoked, time.Now(), reason); err != nil {
		return err
	}
	_, err := p.GenCRL()
	return err
}

// RevokeExpired revokes all expired certificates with the given name.
func (p *PKI) RevokeExpired(name string, reason cert.RevocationReason) error {
	filter := storage.StatusExpired
	entries, err := p.index.Query(storage.IndexFilter{Status: &filter, Name: name})
	if err != nil {
		return err
	}
	now := time.Now()
	for _, e := range entries {
		_ = p.index.Update(e.Serial, storage.StatusRevoked, now, reason)
	}
	_, err = p.GenCRL()
	return err
}

// GenCRL generates and stores a new Certificate Revocation List, returning the PEM bytes.
func (p *PKI) GenCRL() ([]byte, error) {
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

	revokedStatus := storage.StatusRevoked
	entries, err := p.index.Query(storage.IndexFilter{Status: &revokedStatus})
	if err != nil {
		return nil, err
	}

	var revokedEntries []x509.RevocationListEntry
	for _, e := range entries {
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   e.Serial,
			RevocationTime: e.RevokedAt,
			ReasonCode:     int(e.RevocationReason),
		})
	}

	// Determine the CRL number.
	crlNumber := big.NewInt(1)
	if existing, err := p.crlHolder.Get(); err == nil && existing.Number != nil {
		crlNumber = new(big.Int).Add(existing.Number, big.NewInt(1))
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:                    crlNumber,
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(0, 0, p.config.CRLDays),
		RevokedCertificateEntries: revokedEntries,
	}

	signer, ok := caKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("pki: CA key does not implement crypto.Signer")
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, signer)
	if err != nil {
		return nil, err
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if err := p.crlHolder.Put(crlPEM); err != nil {
		return nil, err
	}
	return crlPEM, nil
}

// IsRevoked reports whether the certificate with the given serial is revoked.
func (p *PKI) IsRevoked(serial *big.Int) (bool, error) {
	crl, err := p.crlHolder.Get()
	if err != nil {
		return false, err
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return true, nil
		}
	}
	return false, nil
}
