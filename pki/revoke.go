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

	"github.com/kemsta/go-easyrsa/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/crypto"
	"github.com/kemsta/go-easyrsa/storage"
)

// Revoke revokes all certificates stored under the given name.
func (p *PKI) Revoke(name string, reason cert.RevocationReason) error {
	if err := validateEntityName(name); err != nil {
		return err
	}
	pairs, err := p.storage.GetByName(name)
	if err != nil {
		return err
	}
	now := time.Now()
	var errs []error
	for _, pair := range pairs {
		if pair.CertPEM == nil {
			continue
		}
		serial, err := pair.Serial()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := p.index.Update(serial, storage.StatusRevoked, now, reason); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err // index update(s) failed; do not regenerate CRL from inconsistent state (W4)
	}
	if _, err = p.GenCRL(); err != nil {
		return err
	}
	return nil
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

// RevokeExpired revokes all expired certificates stored under the given name.
// Resolution is by storage key (not Subject CN), so it works correctly in org
// mode when WithSubjectOverride sets a CN that differs from the entity name.
func (p *PKI) RevokeExpired(name string, reason cert.RevocationReason) error {
	if err := validateEntityName(name); err != nil {
		return err
	}
	pairs, err := p.storage.GetByName(name)
	if err != nil {
		return err
	}

	expiredStatus := storage.StatusExpired
	allExpired, err := p.index.Query(storage.IndexFilter{Status: &expiredStatus})
	if err != nil {
		return err
	}

	// Build a set of serials for this storage name.
	type void struct{}
	serials := make(map[string]void, len(pairs))
	for _, pair := range pairs {
		if pair.CertPEM == nil {
			continue
		}
		if serial, err := pair.Serial(); err == nil {
			serials[serial.Text(16)] = void{}
		}
	}

	now := time.Now()
	var errs []error
	for _, e := range allExpired {
		if _, ok := serials[e.Serial.Text(16)]; !ok {
			continue
		}
		if err := p.index.Update(e.Serial, storage.StatusRevoked, now, reason); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err // index update(s) failed; do not regenerate CRL from inconsistent state
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

// ResetCRL removes the stored CRL, allowing GenCRL to start a fresh sequence.
// Call this only after verifying that the current CRL state is acceptable;
// the next GenCRL will restart the CRL number at 1.
func (p *PKI) ResetCRL() error {
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
