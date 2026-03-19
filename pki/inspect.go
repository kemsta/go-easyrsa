package pki

import (
	"crypto/x509"
	"time"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/storage"
)

// ShowCert returns the certificate pair for the given name.
func (p *PKI) ShowCert(name string) (*cert.Pair, error) {
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
	for _, e := range entries {
		if e.ExpiresAt.Before(cutoff) {
			pair, err := p.storage.GetBySerial(e.Serial)
			if err != nil {
				continue
			}
			pairs = append(pairs, pair)
		}
	}
	return pairs, nil
}

// ShowRevoked returns all revoked certificate pairs.
func (p *PKI) ShowRevoked() ([]*cert.Pair, error) {
	revokedStatus := storage.StatusRevoked
	entries, err := p.index.Query(storage.IndexFilter{Status: &revokedStatus})
	if err != nil {
		return nil, err
	}
	var pairs []*cert.Pair
	for _, e := range entries {
		pair, err := p.storage.GetBySerial(e.Serial)
		if err != nil {
			continue
		}
		pairs = append(pairs, pair)
	}
	return pairs, nil
}

// VerifyCert verifies the certificate chain for the named certificate.
func (p *PKI) VerifyCert(name string) error {
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
	return err
}

// UpdateDB scans issued certificates and marks expired ones as expired in the index.
func (p *PKI) UpdateDB() error {
	validStatus := storage.StatusValid
	entries, err := p.index.Query(storage.IndexFilter{Status: &validStatus})
	if err != nil {
		return err
	}
	now := time.Now()
	for _, e := range entries {
		if e.ExpiresAt.Before(now) {
			if err := p.index.Update(e.Serial, storage.StatusExpired, time.Time{}, 0); err != nil {
				return err
			}
		}
	}
	return nil
}
