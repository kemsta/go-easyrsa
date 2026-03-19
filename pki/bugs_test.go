package pki_test

// This file contains tests for bugs identified in the staff engineer code review.
// Every test in this file is expected to FAIL until the corresponding bug is fixed.
//
// B3 — storage.Put succeeds but index.Record fails: cert is stored as an orphan
//       (exists on disk / in memory, invisible to all index-based queries).
//
// B4 — Renew and RenewCA do not invalidate the old certificate in the index:
//       both the old and new certs remain StatusValid simultaneously.
//
// B5 — cert.Pair.CertType() returns CertTypeClient as a catch-all default
//       for any certificate whose EKU is not ServerAuth or ClientAuth.
//
// W3 — memory.KeyStorage.Put appends unconditionally, so GenReq's key-only
//       pair is never cleaned up; GetAll returns orphan intermediate entries.
//
// W4 — pki.Revoke calls GenCRL even when index.Update fails, producing and
//       persisting a CRL built from an inconsistent (partially-updated) index.

import (
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/pki"
	"github.com/kemsta/go-easyrsa/storage"
	"github.com/kemsta/go-easyrsa/storage/memory"
)

// errRecordIndexDB wraps an IndexDB but always returns errOnRecord from Record.
// Used to simulate a disk-full / IO error that occurs after storage.Put but
// before index.Record completes.
type errRecordIndexDB struct {
	inner       storage.IndexDB
	errOnRecord error
}

func (e *errRecordIndexDB) Record(_ storage.IndexEntry) error { return e.errOnRecord }

func (e *errRecordIndexDB) Update(serial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	return e.inner.Update(serial, status, revokedAt, reason)
}

func (e *errRecordIndexDB) Query(filter storage.IndexFilter) ([]storage.IndexEntry, error) {
	return e.inner.Query(filter)
}

// --- B3 ---

// TestSignReq_NoOrphanCertOnIndexRecordFailure — B3
//
// SignReq calls storage.Put(certPair) before index.Record. If index.Record
// returns an error, SignReq correctly returns that error to the caller — but
// the certificate has already been persisted in KeyStorage. The caller sees
// a failure but the cert is silently stored as an orphan: it holds a serial
// number, exists in the filesystem / memory, and is invisible to every
// index-based operation (ShowExpiring, ShowRevoked, GenCRL, VerifyCert).
//
// Expected (correct): after a failed BuildClientFull, KeyStorage must not
//                     contain the cert (operation should be atomic or rolled back).
// Actual (buggy):     GetLastByName returns the cert despite the error.
func TestSignReq_NoOrphanCertOnIndexRecordFailure(t *testing.T) {
	// Build the CA through a clean PKI so index.Record succeeds for the CA entry.
	ks, cs, idx, sp, crl := memory.New()
	goodP := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	_, err := goodP.BuildCA()
	require.NoError(t, err)

	// Inject an index that always fails on Record, simulating an IO error that
	// occurs after the cert bytes have already been written to KeyStorage.
	failIdx := &errRecordIndexDB{inner: idx, errOnRecord: errors.New("index: disk full")}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, failIdx, sp, crl)

	_, err = p.BuildClientFull("client1")
	require.Error(t, err, "BuildClientFull must surface the index.Record failure")

	// The cert must not remain in storage — the operation failed atomically.
	_, storageErr := ks.GetLastByName("client1")
	assert.ErrorIs(t, storageErr, storage.ErrNotFound,
		"orphan cert found in KeyStorage after failed BuildClientFull: "+
			"storage.Put succeeded but index.Record failed, leaving the PKI in an inconsistent state")
}

// --- B4 ---

// TestRenew_OldCertNoLongerValidAfterRenew — B4
//
// After Renew, only the newly issued certificate should have StatusValid in
// the index. The original certificate's index entry must be marked expired
// (or revoked) so it no longer appears in status queries.
//
// If the old entry is left as StatusValid, ShowExpiring returns both the
// old cert (expiring in 1 day) and the new cert, creating confusion and
// potentially misleading alerts. More critically, if the old cert is later
// compromised, it appears valid until it naturally expires.
//
// Expected (correct): ShowExpiring(2) returns 0 certs for client1 after Renew
//                     (old 1-day cert is invalidated; new 825-day cert is not expiring).
// Actual (buggy):     ShowExpiring(2) returns the old cert — still StatusValid.
func TestRenew_OldCertNoLongerValidAfterRenew(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	// Issue a cert that expires in 1 day so it shows up in ShowExpiring(2).
	_, err := p.BuildClientFull("client1", pki.WithDays(1))
	require.NoError(t, err)

	// Renew with a normal 825-day validity.
	_, err = p.Renew("client1")
	require.NoError(t, err)

	// After Renew the original 1-day cert should be invalidated in the index.
	// ShowExpiring(2) queries StatusValid entries expiring within 2 days.
	// If the old entry is properly invalidated it will not appear here.
	expiring, err := p.ShowExpiring(2)
	require.NoError(t, err)

	for _, pair := range expiring {
		if pair.Name == "client1" {
			t.Errorf(
				"old client1 cert (1-day expiry) still appears as StatusValid after Renew: "+
					"Renew must invalidate the previous index entry (serial=%v)",
				func() string {
					if s, e := pair.Serial(); e == nil {
						return s.Text(16)
					}
					return "unknown"
				}(),
			)
		}
	}
}

// TestRenewCA_OldCACertNoLongerValidAfterRenew — B4
//
// After RenewCA, only the new CA certificate should be StatusValid in the index.
// The old CA entry must be invalidated so it does not appear in expiry queries.
//
// Expected (correct): ShowExpiring(2) contains no CA cert after RenewCA
//                     (old 1-day CA is invalidated; new 3650-day CA is not expiring).
// Actual (buggy):     ShowExpiring(2) returns the old CA — still StatusValid.
func TestRenewCA_OldCACertNoLongerValidAfterRenew(t *testing.T) {
	// Build a CA that expires in 1 day so ShowExpiring(2) picks it up.
	p := newTestPKI(pki.Config{NoPass: true, CADays: 1})
	buildTestCA(t, p)

	_, err := p.RenewCA(pki.WithDays(3650))
	require.NoError(t, err)

	expiring, err := p.ShowExpiring(2)
	require.NoError(t, err)

	for _, pair := range expiring {
		isCA, _ := pair.IsCA()
		if isCA {
			t.Errorf(
				"old CA cert (1-day expiry) still appears as StatusValid after RenewCA: "+
					"RenewCA must invalidate the previous CA index entry (serial=%v)",
				func() string {
					if s, e := pair.Serial(); e == nil {
						return s.Text(16)
					}
					return "unknown"
				}(),
			)
		}
	}
}

// --- B5 ---

// TestCertType_UnrecognizedEKUIsNotSilentlyClient — B5
//
// cert.Pair.CertType() uses a default: branch that returns CertTypeClient
// for any certificate whose ExtKeyUsage contains neither ServerAuth nor
// ClientAuth (e.g. CodeSigning, TimeStamping, OCSPSigning, no EKU at all).
//
// Silently misclassifying such certificates as "client" certs causes
// incorrect behaviour in any caller that branches on CertType().
//
// Expected (correct): CertType() returns ("", error) for an unrecognised EKU.
// Actual (buggy):     CertType() returns (CertTypeClient, nil).
func TestCertType_UnrecognizedEKUIsNotSilentlyClient(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	// Build a cert whose EKU contains only CodeSigning — not Server or Client auth.
	pair, err := p.BuildClientFull("codesign",
		pki.WithCertModifier(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}),
	)
	require.NoError(t, err)

	certType, err := pair.CertType()
	if err == nil {
		// No error returned: check that at least the classification is not silently wrong.
		assert.NotEqual(t, cert.CertTypeClient, certType,
			"cert with only CodeSigning EKU was silently misclassified as CertTypeClient; "+
				"CertType() must return an error for unrecognised EKU combinations")
	}
	// Primary expectation: an unrecognised EKU should produce an error, not a guess.
	assert.Error(t, err,
		"CertType() must return an error for a cert with an unrecognised EKU (CodeSigning), "+
			"not silently fall through to CertTypeClient")
}

// --- W3 ---

// TestMemoryKeyStorage_NoOrphanPairsAfterBuildFull — W3
//
// memory.KeyStorage.Put unconditionally appends to the internal slice.
// BuildClientFull calls GenReq (which stores a key-only Pair with CertPEM==nil)
// followed by SignReq (which stores the complete Pair with both key and cert).
// The key-only intermediate entry is never cleaned up, so GetAll returns it
// alongside the real cert — inflating results and leaking memory over time.
//
// Expected (correct): GetAll returns exactly 2 pairs: CA + client1 cert.
// Actual (buggy):     GetAll returns 3 pairs: CA + orphan key-only + client1 cert.
func TestMemoryKeyStorage_NoOrphanPairsAfterBuildFull(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, p)

	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	all, err := ks.GetAll()
	require.NoError(t, err)

	assert.Len(t, all, 2,
		"GetAll should return exactly CA + client1 (2 entries); "+
			"extra entries are orphan key-only pairs left by the intermediate GenReq step")

	// Secondary check: every returned pair must have a certificate.
	for _, pair := range all {
		assert.NotNil(t, pair.CertPEM,
			"GetAll returned a key-only pair (CertPEM==nil) for name %q; "+
				"intermediate GenReq pairs must not survive after SignReq completes", pair.Name)
	}
}

// --- W4 ---

// TestRevoke_DoesNotUpdateCRLWhenIndexUpdateFails — W4
//
// pki.Revoke continues to call GenCRL even when index.Update returns an error.
// Because Update failed, no entries were marked as revoked in the index.
// GenCRL therefore builds a CRL with zero revocations and persists it —
// overwriting any previously correct CRL and advancing the CRL number,
// all while returning an error to the caller.
//
// Expected (correct): if index.Update fails, Revoke must return an error
//                     and must NOT call GenCRL (CRL state must remain unchanged).
// Actual (buggy):     CRL is regenerated (with zero revocations) despite the error.
func TestRevoke_DoesNotUpdateCRLWhenIndexUpdateFails(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	errIdx := &errUpdateIndexDB{inner: idx, errOnUpdate: errors.New("index: disk full")}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, errIdx, sp, crl)

	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	// Record the CRL state before the failing Revoke.
	// No GenCRL has been called yet, so the CRL holder is empty (Number == nil).
	crlBefore, err := crl.Get()
	require.NoError(t, err)

	revokeErr := p.Revoke("client1", cert.ReasonUnspecified)
	require.Error(t, revokeErr, "Revoke must return an error when index.Update fails")

	// The CRL must not have been touched — GenCRL should not run on index failure.
	crlAfter, err := crl.Get()
	require.NoError(t, err)

	assert.Equal(t, crlBefore.Number, crlAfter.Number,
		"CRL number advanced from %v to %v after a failed Revoke: "+
			"GenCRL must not be called when index.Update returns an error",
		crlBefore.Number, crlAfter.Number)
}
