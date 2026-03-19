package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
)

// ShowCert returns the certificate pair for the given name.
func (p *PKI) ShowCert(name string) (*cert.Pair, error) {
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	return p.storage.GetLastByName(name)
}

// ShowCRL returns the current Certificate Revocation List.
func (p *PKI) ShowCRL() (*x509.RevocationList, error) {
	return p.crlHolder.Get()
}

// ShowExpiring returns certificates expiring within withinDays days.
func (p *PKI) ShowExpiring(withinDays int) ([]*cert.Pair, error) {
	validStatus := storage.StatusValid
	entries, err := p.index.Query(storage.IndexFilter{Status: &validStatus})
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().AddDate(0, 0, withinDays)
	var pairs []*cert.Pair
	var errs []error
	for _, e := range entries {
		if e.ExpiresAt.Before(cutoff) {
			pair, err := p.storage.GetBySerial(e.Serial)
			if err != nil {
				errs = append(errs, fmt.Errorf("serial %s: %w", e.Serial.Text(16), err))
				continue
			}
			pairs = append(pairs, pair)
		}
	}
	return pairs, errors.Join(errs...)
}

// ShowRevoked returns all revoked certificate pairs.
func (p *PKI) ShowRevoked() ([]*cert.Pair, error) {
	revokedStatus := storage.StatusRevoked
	entries, err := p.index.Query(storage.IndexFilter{Status: &revokedStatus})
	if err != nil {
		return nil, err
	}
	var pairs []*cert.Pair
	var errs []error
	for _, e := range entries {
		pair, err := p.storage.GetBySerial(e.Serial)
		if err != nil {
			errs = append(errs, fmt.Errorf("serial %s: %w", e.Serial.Text(16), err))
			continue
		}
		pairs = append(pairs, pair)
	}
	return pairs, errors.Join(errs...)
}

// VerifyCert verifies the certificate chain for the named certificate.
func (p *PKI) VerifyCert(name string) error {
	if err := validateEntityName(name); err != nil {
		return err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return err
	}

	caPair, err := p.storage.GetLastByName(p.config.CAName)
	if err != nil {
		return err
	}
	caCert, err := caPair.Certificate()
	if err != nil {
		return err
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = certificate.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return err
	}

	// Check CRL if available.
	crl, err := p.crlHolder.Get()
	if err != nil {
		return err
	}
	if len(crl.Signature) > 0 {
		if err := crl.CheckSignatureFrom(caCert); err != nil {
			return fmt.Errorf("pki: CRL signature verification failed: %w", err)
		}
		serial, err := pair.Serial()
		if err != nil {
			return err
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(serial) == 0 {
				return errors.New("pki: certificate is revoked")
			}
		}
	}
	return nil
}

// UpdateDB scans issued certificates and marks expired ones as expired in the index.
func (p *PKI) UpdateDB() error {
	validStatus := storage.StatusValid
	entries, err := p.index.Query(storage.IndexFilter{Status: &validStatus})
	if err != nil {
		return err
	}
	now := time.Now()
	var errs []error
	for _, e := range entries {
		if e.ExpiresAt.Before(now) {
			if err := p.index.Update(e.Serial, storage.StatusExpired, time.Time{}, 0); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
