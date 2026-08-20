package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// RenewalInfo describes an unrevoked certificate in an Easy-RSA renewal
// archive. Mutable values are detached from backend state.
type RenewalInfo struct {
	Name           string
	Serial         *big.Int
	Status         storage.CertStatus
	ExpiresAt      time.Time
	CommonName     string
	CertificatePEM []byte
	RequiresRewind bool
}

// ShowRenewed reports renewed certificates that have not been revoked.
func (p *PKI) ShowRenewed() ([]RenewalInfo, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) ([]RenewalInfo, error) { return bound.ShowRenewed() })
	}
	archives, err := p.lifecycle.ListRenewed()
	if err != nil {
		return nil, err
	}
	type renewalCandidate struct {
		archive     storage.RenewalArchive
		certificate *x509.Certificate
	}
	named := make(map[string]renewalCandidate)
	bySerial := make(map[string]renewalCandidate)
	for _, archive := range archives {
		if archive.Serial == nil || archive.Serial.Sign() <= 0 {
			return nil, errors.New("pki: renewed archive has invalid serial")
		}
		serialKey := storage.HexSerial(archive.Serial)
		certificate, err := (&cert.Pair{Name: archive.Name, CertPEM: archive.CertificatePEM}).Certificate()
		if err != nil {
			return nil, fmt.Errorf("pki: parse renewed certificate %s: %w", serialKey, err)
		}
		if certificate.SerialNumber.Cmp(archive.Serial) != 0 {
			return nil, fmt.Errorf("pki: renewed archive serial %s does not match certificate", serialKey)
		}
		candidate := renewalCandidate{archive: archive, certificate: certificate}
		switch archive.Source {
		case storage.RenewalArchiveIssued:
			if err := validateEntityName(archive.Name); err != nil {
				return nil, err
			}
			if _, exists := named[archive.Name]; exists {
				return nil, errors.Join(storage.ErrConflict, fmt.Errorf("pki: duplicate named renewal archive %q", archive.Name))
			}
			named[archive.Name] = candidate
		case storage.RenewalArchiveBySerial:
			if archive.Name != "" {
				return nil, fmt.Errorf("pki: historical renewal archive %s has an entity name", serialKey)
			}
			if _, exists := bySerial[serialKey]; exists {
				return nil, errors.Join(storage.ErrConflict, fmt.Errorf("pki: duplicate historical renewal archive %s", serialKey))
			}
			bySerial[serialKey] = candidate
		default:
			return nil, fmt.Errorf("pki: unsupported renewal archive source %q", archive.Source)
		}
	}

	entries, err := p.index.Query(storage.IndexFilter{})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	results := make([]RenewalInfo, 0, len(archives))
	for _, entry := range entries {
		if entry.Status != storage.StatusValid && entry.Status != storage.StatusExpired {
			continue
		}
		if entry.Serial == nil || entry.Serial.Sign() <= 0 {
			return nil, errors.New("pki: renewal index entry has invalid serial")
		}
		serialKey := storage.HexSerial(entry.Serial)
		namedCandidate, hasNamed := named[entry.Subject.CommonName]
		if hasNamed && namedCandidate.archive.Serial.Cmp(entry.Serial) != 0 {
			hasNamed = false
		}
		historicalCandidate, hasHistorical := bySerial[serialKey]
		if hasNamed && hasHistorical {
			return nil, errors.Join(storage.ErrConflict, fmt.Errorf("pki: renewed serial %s exists in both archive sources", serialKey))
		}
		if !hasNamed && !hasHistorical {
			continue
		}
		candidate := namedCandidate
		requiresRewind := false
		name := namedCandidate.archive.Name
		if hasHistorical {
			candidate = historicalCandidate
			requiresRewind = true
			name = entry.Subject.CommonName
		}
		archive := candidate.archive
		certificate := candidate.certificate
		if certificate.SerialNumber.Cmp(entry.Serial) != 0 {
			return nil, fmt.Errorf("pki: renewed certificate serial %s does not match index", serialKey)
		}
		if certificate.Subject.CommonName != entry.Subject.CommonName {
			return nil, fmt.Errorf("pki: renewed certificate common name does not match index for serial %s", serialKey)
		}
		status := storage.StatusValid
		if !certificate.NotAfter.After(now) {
			status = storage.StatusExpired
		}
		results = append(results, RenewalInfo{
			Name:           name,
			Serial:         new(big.Int).Set(entry.Serial),
			Status:         status,
			ExpiresAt:      certificate.NotAfter,
			CommonName:     entry.Subject.CommonName,
			CertificatePEM: append([]byte(nil), archive.CertificatePEM...),
			RequiresRewind: requiresRewind,
		})
	}
	return results, nil
}

// RevokeRenewed revokes a named renewal archive while preserving the current
// replacement certificate, private key, and request. It does not generate a
// CRL; GenCRL remains a separate operation.
func (p *PKI) RevokeRenewed(name string, reason cert.RevocationReason) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.RevokeRenewed(name, reason) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
	if err := validateRevocationReason(reason); err != nil {
		return err
	}
	certificatePEM, err := p.lifecycle.GetRenewedCertificate(name)
	if err != nil {
		return err
	}
	certificate, err := validateLifecycleCertificate(&cert.Pair{Name: name, CertPEM: certificatePEM})
	if err != nil {
		return err
	}
	if err := p.lifecycle.MoveRenewedToRevoked(name, certificate.SerialNumber); err != nil {
		return err
	}
	if err := p.removeDerivedArtifacts(name); err != nil {
		return err
	}
	return p.index.Update(certificate.SerialNumber, storage.StatusRevoked, time.Now(), reason)
}
