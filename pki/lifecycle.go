package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// Expire moves the current issued certificate to expired/NAME.crt without
// changing its index status. The certificate remains valid until its actual
// expiry or a later UpdateDB call.
func (p *PKI) Expire(name string) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.Expire(name) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	certificate, err := validateLifecycleCertificate(pair)
	if err != nil {
		return err
	}
	return p.lifecycle.MoveIssuedToExpired(name, certificate.SerialNumber)
}

// RevokeIssued archives the current issued certificate, key, and CSR, removes
// derived exports, and records revocation in the index. It deliberately does
// not generate a CRL; GenCRL is a separate Easy-RSA operation.
func (p *PKI) RevokeIssued(name string, reason cert.RevocationReason) error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.RevokeIssued(name, reason) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
	if err := validateRevocationReason(reason); err != nil {
		return err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	certificate, err := validateLifecycleCertificate(pair)
	if err != nil {
		return err
	}
	if err := p.lifecycle.MoveIssuedToRevoked(name, certificate.SerialNumber); err != nil {
		return err
	}
	if err := p.removeDerivedArtifacts(name); err != nil {
		return err
	}
	return p.index.Update(certificate.SerialNumber, storage.StatusRevoked, time.Now(), reason)
}

func (p *PKI) revokeExpired(name string, reason cert.RevocationReason) error {
	certificatePEM, err := p.lifecycle.GetExpiredCertificate(name)
	if err != nil {
		return err
	}
	pair := &cert.Pair{Name: name, CertPEM: certificatePEM}
	certificate, err := validateLifecycleCertificate(pair)
	if err != nil {
		return err
	}
	if err := p.lifecycle.MoveExpiredToRevoked(name, certificate.SerialNumber); err != nil {
		return err
	}
	// Easy-RSA removes name-based PKCS and inline artifacts for every revoke
	// variant, including revoke-expired, even when a replacement is current.
	if err := p.removeDerivedArtifacts(name); err != nil {
		return err
	}
	return p.index.Update(certificate.SerialNumber, storage.StatusRevoked, time.Now(), reason)
}

func (p *PKI) removeDerivedArtifacts(name string) error {
	for _, artifactPath := range []string{
		path.Join("private", name+".p12"),
		path.Join("private", name+".p8"),
		path.Join("private", name+".p1"),
		path.Join("issued", name+".p7b"),
		path.Join("inline", name+".inline"),
		path.Join("inline", "private", name+".inline"),
	} {
		if err := p.artifacts.DeleteArtifact(artifactPath); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	return nil
}

func validateLifecycleCertificate(pair *cert.Pair) (*x509.Certificate, error) {
	certificate, err := pair.Certificate()
	if err != nil {
		return nil, err
	}
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err == nil {
		return nil, errors.New("pki: cannot apply lifecycle operation to a self-signed certificate")
	}
	return certificate, nil
}

func validateRevocationReason(reason cert.RevocationReason) error {
	switch reason {
	case cert.ReasonUnspecified,
		cert.ReasonKeyCompromise,
		cert.ReasonCACompromise,
		cert.ReasonAffiliationChanged,
		cert.ReasonSuperseded,
		cert.ReasonCessationOfOperation:
		return nil
	default:
		return fmt.Errorf("pki: unsupported revocation reason %d", reason)
	}
}
