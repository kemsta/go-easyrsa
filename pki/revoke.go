package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// Revoke is Easy-RSA's current-issued revoke operation. RevokeIssued is the
// explicit alias used when other lifecycle locations conflict.
func (p *PKI) Revoke(name string, reason cert.RevocationReason) error {
	return p.RevokeIssued(name, reason)
}

// RevokeBySerial revokes the certificate identified by the given serial number.
func (p *PKI) RevokeBySerial(serial *big.Int, reason cert.RevocationReason) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.RevokeBySerial(serial, reason) })
	}
	if err := storage.ValidateSerial(serial); err != nil {
		return err
	}
	if err := validateRevocationReason(reason); err != nil {
		return err
	}
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

// RevokeExpired archives expired/NAME.crt and records revocation without
// moving the current key or CSR and without generating a CRL.
func (p *PKI) RevokeExpired(name string, reason cert.RevocationReason) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.RevokeExpired(name, reason) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
	if err := validateRevocationReason(reason); err != nil {
		return err
	}
	return p.revokeExpired(name, reason)
}

// GenCRL generates and stores a new Certificate Revocation List, returning the PEM bytes.
func (p *PKI) GenCRL() ([]byte, error) {
	if !p.bound() {
		return withUpdate(p, func(bound *PKI) ([]byte, error) { return bound.GenCRL() })
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

	// Determine the CRL number. A missing CRL starts at 1; any read error is fatal
	// to prevent silent CRL number resets (RFC 5280 § 5.2.3 requires monotonic increase).
	crlNumber := big.NewInt(1)
	existing, err := p.crlHolder.Get()
	if err != nil {
		return nil, fmt.Errorf("pki: read existing CRL: %w", err)
	}
	if existing.Number != nil {
		crlNumber = new(big.Int).Add(existing.Number, big.NewInt(1))
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:                    crlNumber,
		ThisUpdate:                now,
		NextUpdate:                addExactDays(now, p.config.CRLDays),
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
	for _, artifact := range []storage.Artifact{
		{Path: "crl.pem", Data: crlPEM, Visibility: storage.ArtifactPublic},
		{Path: "crl.der", Data: crlDER, Visibility: storage.ArtifactPublic},
	} {
		if err := p.artifacts.PutArtifact(artifact); err != nil {
			return nil, err
		}
	}
	return crlPEM, nil
}

// ResetCRL removes the stored CRL, allowing GenCRL to start a fresh sequence.
// Call this only after verifying that the current CRL state is acceptable;
// the next GenCRL will restart the CRL number at 1.
func (p *PKI) ResetCRL() error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.ResetCRL() })
	}
	for _, name := range []string{"crl.der", "crl.pem"} {
		if err := p.artifacts.DeleteArtifact(name); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	// CRLHolder implementations that store to a file expose a Delete method.
	type deleter interface {
		Delete() error
	}
	if d, ok := p.crlHolder.(deleter); ok {
		return d.Delete()
	}
	// In-memory holders treat Put(nil) as a reset (Get() returns empty list).
	return p.crlHolder.Put(nil)
}

// IsRevoked reports whether the certificate with the given serial is revoked.
func (p *PKI) IsRevoked(serial *big.Int) (bool, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) (bool, error) { return bound.IsRevoked(serial) })
	}
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
