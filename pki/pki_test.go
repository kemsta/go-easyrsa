package pki_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/cert"
	"github.com/kemsta/go-easyrsa/pki"
	"github.com/kemsta/go-easyrsa/storage"
	"github.com/kemsta/go-easyrsa/storage/memory"
)

// --- Test helpers & mock types ---

// errUpdateIndexDB wraps an IndexDB but always returns errOnUpdate from Update.
type errUpdateIndexDB struct {
	inner       storage.IndexDB
	errOnUpdate error
}

func (e *errUpdateIndexDB) Record(entry storage.IndexEntry) error {
	return e.inner.Record(entry)
}

func (e *errUpdateIndexDB) Update(_ *big.Int, _ storage.CertStatus, _ time.Time, _ cert.RevocationReason) error {
	return e.errOnUpdate
}

func (e *errUpdateIndexDB) RecordAndUpdate(newEntry storage.IndexEntry, oldSerial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	if err := e.inner.Record(newEntry); err != nil {
		return err
	}
	return e.errOnUpdate
}

func (e *errUpdateIndexDB) Query(filter storage.IndexFilter) ([]storage.IndexEntry, error) {
	return e.inner.Query(filter)
}

// errRecordIndexDB wraps an IndexDB but always returns errOnRecord from Record.
type errRecordIndexDB struct {
	inner       storage.IndexDB
	errOnRecord error
}

func (e *errRecordIndexDB) Record(_ storage.IndexEntry) error { return e.errOnRecord }

func (e *errRecordIndexDB) Update(serial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	return e.inner.Update(serial, status, revokedAt, reason)
}

func (e *errRecordIndexDB) RecordAndUpdate(newEntry storage.IndexEntry, oldSerial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	return e.errOnRecord
}

func (e *errRecordIndexDB) Query(filter storage.IndexFilter) ([]storage.IndexEntry, error) {
	return e.inner.Query(filter)
}

// errCRLHolder wraps a CRLHolder but always returns errOnGet from Get.
type errCRLHolder struct {
	inner    storage.CRLHolder
	errOnGet error
}

func (e *errCRLHolder) Put(pemBytes []byte) error { return e.inner.Put(pemBytes) }
func (e *errCRLHolder) Get() (*x509.RevocationList, error) {
	return nil, e.errOnGet
}

// certPutFailKeyStorage wraps a KeyStorage. It allows the first certPutsAllowed cert-bearing
// Puts (pairs with CertPEM set), then returns errDiskFull for subsequent cert Puts.
// Key-only Puts (from GenReq, CertPEM==nil) are always allowed.
type certPutFailKeyStorage struct {
	inner           storage.KeyStorage
	certPutsAllowed int
	certPutsSeen    int
}

func (e *certPutFailKeyStorage) Put(pair *cert.Pair) error {
	if pair.CertPEM == nil {
		return e.inner.Put(pair) // key-only Put: always allow
	}
	e.certPutsSeen++
	if e.certPutsSeen <= e.certPutsAllowed {
		return e.inner.Put(pair)
	}
	return errDiskFull // cert Put: fail after the allowed count
}

func (e *certPutFailKeyStorage) GetLastByName(name string) (*cert.Pair, error) {
	return e.inner.GetLastByName(name)
}
func (e *certPutFailKeyStorage) GetByName(name string) ([]*cert.Pair, error) {
	return e.inner.GetByName(name)
}
func (e *certPutFailKeyStorage) GetBySerial(serial *big.Int) (*cert.Pair, error) {
	return e.inner.GetBySerial(serial)
}
func (e *certPutFailKeyStorage) DeleteByName(name string) error {
	return e.inner.DeleteByName(name)
}
func (e *certPutFailKeyStorage) DeleteBySerial(serial *big.Int) error {
	return e.inner.DeleteBySerial(serial)
}
func (e *certPutFailKeyStorage) GetAll() ([]*cert.Pair, error) { return e.inner.GetAll() }

var _ storage.KeyStorage = (*certPutFailKeyStorage)(nil)

// errPutCSRStorage wraps a CSRStorage and returns errOnPut from PutCSR.
type errPutCSRStorage struct {
	inner    storage.CSRStorage
	errOnPut error
}

func (e *errPutCSRStorage) PutCSR(name string, csrPEM []byte) error { return e.errOnPut }
func (e *errPutCSRStorage) GetCSR(name string) ([]byte, error)      { return e.inner.GetCSR(name) }
func (e *errPutCSRStorage) DeleteCSR(name string) error             { return e.inner.DeleteCSR(name) }
func (e *errPutCSRStorage) ListCSRs() ([]string, error)             { return e.inner.ListCSRs() }

var _ storage.CSRStorage = (*errPutCSRStorage)(nil)

// errDiskFull is a shared sentinel used by test mock types.
var errDiskFull = errors.New("simulated disk full")

// newTestPKI creates a PKI instance backed by in-memory storage.
func newTestPKI(cfg pki.Config) *pki.PKI {
	ks, cs, idx, sp, crl := memory.New()
	return pki.New(cfg, ks, cs, idx, sp, crl)
}

func buildTestCA(t *testing.T, p *pki.PKI, opts ...pki.Option) {
	t.Helper()
	_, err := p.BuildCA(opts...)
	require.NoError(t, err)
}

// corruptCSRSignature returns a PEM-encoded CSR identical to the input but with
// the last byte of the DER flipped, making the signature invalid.
func corruptCSRSignature(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	der := make([]byte, len(block.Bytes))
	copy(der, block.Bytes)
	der[len(der)-1] ^= 0xff // flip last byte of DER (signature bytes)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// --- ShowCA ---

func TestShowCA_NotFound(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	_, err := p.ShowCA()
	assert.Error(t, err)
}

func TestShowCA_Found(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	pair, err := p.ShowCA()
	require.NoError(t, err)
	assert.Equal(t, "ca", pair.Name)
	isCA, err := pair.IsCA()
	require.NoError(t, err)
	assert.True(t, isCA)
}

// --- BuildCA ---

func TestBuildCA_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	pair, err := p.BuildCA()
	require.NoError(t, err)
	require.NotNil(t, pair)
	assert.Equal(t, "ca", pair.Name)
	assert.NotEmpty(t, pair.CertPEM)
	assert.NotEmpty(t, pair.KeyPEM)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.True(t, c.IsCA)
	assert.True(t, c.BasicConstraintsValid)
}

func TestBuildCA_WithDays(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	pair, err := p.BuildCA(pki.WithDays(365))
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	expected := time.Now().AddDate(0, 0, 365)
	assert.WithinDuration(t, expected, c.NotAfter, 5*time.Second)
}

func TestBuildCA_WithCN(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	pair, err := p.BuildCA(pki.WithCN("MyCA"))
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, "MyCA", c.Subject.CommonName)
}

func TestBuildCA_ECDSA(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	pair, err := p.BuildCA(pki.WithKeyAlgo(pki.AlgoECDSA), pki.WithCurve(elliptic.P256()))
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.True(t, c.IsCA)
}

func TestBuildCA_Ed25519(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	pair, err := p.BuildCA(pki.WithKeyAlgo(pki.AlgoEd25519))
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.True(t, c.IsCA)
}

func TestBuildCA_NoPassRequired(t *testing.T) {
	p := newTestPKI(pki.Config{}) // NoPass: false, no per-op override
	_, err := p.BuildCA()
	assert.Error(t, err)
}

func TestBuildCA_CNOnly(t *testing.T) {
	cfg := pki.Config{
		NoPass:       true,
		DNMode:       pki.DNModeCNOnly,
		SubjTemplate: pkix.Name{Organization: []string{"Acme Corp"}},
	}
	p := newTestPKI(cfg)
	pair, err := p.BuildCA(pki.WithCN("MyCA"))
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, "MyCA", c.Subject.CommonName)
	assert.Empty(t, c.Subject.Organization)
}

func TestBuildCA_OrgMode(t *testing.T) {
	cfg := pki.Config{
		NoPass:       true,
		DNMode:       pki.DNModeOrg,
		SubjTemplate: pkix.Name{Organization: []string{"Acme Corp"}},
	}
	p := newTestPKI(cfg)
	pair, err := p.BuildCA(pki.WithCN("MyCA"))
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.Equal(t, "MyCA", c.Subject.CommonName)
	assert.Equal(t, []string{"Acme Corp"}, c.Subject.Organization)
}

// TestBuildCA_NoOrphanCertOnIndexRecordFailure verifies that if index.Record
// fails during BuildCA, no orphan cert is left in storage.
func TestBuildCA_NoOrphanCertOnIndexRecordFailure(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	failIdx := &errRecordIndexDB{inner: idx, errOnRecord: errDiskFull}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, failIdx, sp, crl)

	_, err := p.BuildCA()
	require.Error(t, err, "BuildCA must surface the index.Record failure")

	_, storageErr := ks.GetLastByName("ca")
	assert.ErrorIs(t, storageErr, storage.ErrNotFound,
		"orphan CA cert found in KeyStorage after failed BuildCA: "+
			"storage.Put succeeded but index.Record failed, leaving the PKI in an inconsistent state")
}

// --- RenewCA ---

func TestRenewCA_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	origPair, _ := p.ShowCA()
	origCert, _ := origPair.Certificate()
	origNotAfter := origCert.NotAfter

	renewed, err := p.RenewCA(pki.WithDays(9999))
	require.NoError(t, err)

	newCert, err := renewed.Certificate()
	require.NoError(t, err)
	assert.True(t, newCert.NotAfter.After(origNotAfter))
	assert.Equal(t, origCert.PublicKey, newCert.PublicKey)
}

func TestRenewCA_NoCA(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	_, err := p.RenewCA()
	assert.Error(t, err)
}

// TestRenewCA_OldCACertNoLongerValidAfterRenew verifies that after RenewCA,
// the old CA cert is invalidated in the index.
func TestRenewCA_OldCACertNoLongerValidAfterRenew(t *testing.T) {
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

// TestRenewCA_OldCertIndexUpdateFailureIsReturned verifies that RenewCA
// propagates the index.Update failure for the old CA serial.
func TestRenewCA_OldCertIndexUpdateFailureIsReturned(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	goodP := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, goodP)

	failIdx := &errUpdateIndexDB{inner: idx, errOnUpdate: errDiskFull}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, failIdx, sp, crl)

	_, err := p.RenewCA()
	assert.Error(t, err,
		"RenewCA must propagate the index.Update failure for the old CA serial; "+
			"silencing it with `_ =` leaves the old CA cert as StatusValid")
}

// --- GenReq / ImportReq / SignReq ---

func TestGenReq_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	csrPEM, err := p.GenReq("client1")
	require.NoError(t, err)
	assert.NotEmpty(t, csrPEM)
}

// TestGenReq_PathTraversalInName verifies that GenReq rejects names with path traversal.
func TestGenReq_PathTraversalInName(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	_, err := p.GenReq("../evil")
	assert.Error(t, err,
		"GenReq('../evil') must return an error; "+
			"name is used in the CSR path 'reqs/../evil.req' which escapes the reqs/ directory")
}

// TestGenReq_OrphanKeyCleanupOnCSRStorageFailure verifies that if PutCSR fails,
// GenReq cleans up the orphaned private key.
func TestGenReq_OrphanKeyCleanupOnCSRStorageFailure(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	goodP := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, goodP)

	failCS := &errPutCSRStorage{inner: cs, errOnPut: errDiskFull}
	p := pki.New(pki.Config{NoPass: true}, ks, failCS, idx, sp, crl)

	_, err := p.GenReq("client1")
	require.Error(t, err, "setup: GenReq must fail when PutCSR fails")

	_, storageErr := ks.GetLastByName("client1")
	assert.ErrorIs(t, storageErr, storage.ErrNotFound,
		"orphaned private key found in KeyStorage after GenReq failed; "+
			"when PutCSR fails, GenReq must clean up the key it wrote to KeyStorage.")
}

func TestImportReq_Valid(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	csrPEM, _ := p.GenReq("client1")

	p2 := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p2)
	err := p2.ImportReq("req1", csrPEM)
	require.NoError(t, err)
}

func TestImportReq_InvalidPEM(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	err := p.ImportReq("req1", []byte("not a PEM"))
	assert.Error(t, err)
}

func TestSignReq_ClientCert(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	_, err := p.GenReq("client1")
	require.NoError(t, err)

	pair, err := p.SignReq("client1", cert.CertTypeClient)
	require.NoError(t, err)
	assert.Equal(t, "client1", pair.Name)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestSignReq_ServerCert(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	_, err := p.GenReq("server1")
	require.NoError(t, err)

	pair, err := p.SignReq("server1", cert.CertTypeServer)
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestSignReq_NoCSR(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	_, err := p.SignReq("notexist", cert.CertTypeClient)
	assert.Error(t, err)
}

func TestSignReq_NoCA(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	_, err := p.GenReq("client1")
	require.NoError(t, err)

	_, err = p.SignReq("client1", cert.CertTypeClient)
	assert.Error(t, err)
}

// TestSignReq_NoOrphanCertOnIndexRecordFailure verifies that if index.Record
// fails during SignReq (via BuildClientFull), no orphan cert is left.
func TestSignReq_NoOrphanCertOnIndexRecordFailure(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	goodP := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	_, err := goodP.BuildCA()
	require.NoError(t, err)

	failIdx := &errRecordIndexDB{inner: idx, errOnRecord: errors.New("index: disk full")}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, failIdx, sp, crl)

	_, err = p.BuildClientFull("client1")
	require.Error(t, err, "BuildClientFull must surface the index.Record failure")

	_, storageErr := ks.GetLastByName("client1")
	assert.ErrorIs(t, storageErr, storage.ErrNotFound,
		"orphan cert found in KeyStorage after failed BuildClientFull: "+
			"storage.Put succeeded but index.Record failed, leaving the PKI in an inconsistent state")
}

// TestSignReq_StoragePutFailureNoPhantomIndexEntry verifies that if storage.Put
// fails during SignReq, no phantom Valid entry remains in the index.
func TestSignReq_StoragePutFailureNoPhantomIndexEntry(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	goodP := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, goodP)

	_, err := goodP.GenReq("client1")
	require.NoError(t, err)

	failKS := &certPutFailKeyStorage{inner: ks, certPutsAllowed: 0}
	p := pki.New(pki.Config{NoPass: true}, failKS, cs, idx, sp, crl)

	_, err = p.SignReq("client1", cert.CertTypeClient)
	require.Error(t, err, "setup: SignReq must fail when storage.Put fails")

	validStatus := storage.StatusValid
	entries, queryErr := idx.Query(storage.IndexFilter{Status: &validStatus})
	require.NoError(t, queryErr)

	assert.LessOrEqual(t, len(entries), 1,
		"index must not contain a phantom Valid entry after SignReq failed; "+
			"got %d Valid entries (expected at most 1 for the CA).", len(entries))
}

// TestSignReq_PathTraversalInName verifies that SignReq rejects names with path traversal.
func TestSignReq_PathTraversalInName(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, p)

	csrPEM, err := p.GenReq("legit")
	require.NoError(t, err)
	require.NoError(t, cs.PutCSR("../evil", csrPEM))

	_, err = p.SignReq("../evil", cert.CertTypeClient)
	assert.Error(t, err,
		"SignReq('../evil') must return an error for a name containing path separators; "+
			"without validation, the cert is written to 'issued/../evil.crt' which escapes issued/")
}

// TestSignReq_UnknownCertTypeReturnsError verifies that SignReq returns an error
// for an unrecognised CertType instead of silently issuing a ClientAuth cert.
func TestSignReq_UnknownCertTypeReturnsError(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	_, err := p.GenReq("entity1")
	require.NoError(t, err)

	_, err = p.SignReq("entity1", cert.CertType("totally-unknown-type"))
	assert.Error(t, err,
		"SignReq must return an error for an unrecognised CertType; "+
			"silently issuing a ClientAuth cert hides caller bugs and produces "+
			"incorrectly typed certificates without any diagnostic")
}

// TestSignReq_InvalidCSRSignatureIsRejected verifies that SignReq verifies the
// CSR self-signature (proof-of-possession) before issuing a certificate.
func TestSignReq_InvalidCSRSignatureIsRejected(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, p)

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "forge-test"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)

	orig, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.NoError(t, orig.CheckSignature(), "test setup: original CSR must have valid signature")

	corruptCSR := corruptCSRSignature(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	block2, _ := pem.Decode(corruptCSR)
	require.NotNil(t, block2)
	corrupted, err := x509.ParseCertificateRequest(block2.Bytes)
	if err == nil {
		if sigErr := corrupted.CheckSignature(); sigErr == nil {
			t.Skip("signature corruption did not produce an invalid signature on this platform; skipping")
		}
	}

	require.NoError(t, cs.PutCSR("forge-test", corruptCSR))

	_, err = p.SignReq("forge-test", cert.CertTypeClient)
	assert.Error(t, err,
		"SignReq must verify the CSR self-signature (proof-of-possession) per RFC 2986 § 3; "+
			"without this check a tampered CSR with an invalid signature is silently accepted")
}

// --- BuildClientFull / BuildServerFull / BuildServerClientFull ---

func TestBuildClientFull_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	pair, err := p.BuildClientFull("client1")
	require.NoError(t, err)
	assert.Equal(t, "client1", pair.Name)
	assert.NotEmpty(t, pair.CertPEM)
	assert.NotEmpty(t, pair.KeyPEM)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.False(t, c.IsCA)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestBuildServerFull_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	pair, err := p.BuildServerFull("server1")
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestBuildServerClientFull_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	pair, err := p.BuildServerClientFull("sc1")
	require.NoError(t, err)

	c, err := pair.Certificate()
	require.NoError(t, err)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestBuildClientFull_NoCA(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	_, err := p.BuildClientFull("client1")
	assert.Error(t, err)
}

// TestBuildClientFull_PathTraversalInName verifies that BuildClientFull rejects
// names containing path separators or other dangerous patterns.
func TestBuildClientFull_PathTraversalInName(t *testing.T) {
	malicious := []string{
		"../evil",
		"../../etc/cron.d/backdoor",
		"foo/bar",
		"foo\\bar",
		"..",
		".",
		"",
		"foo\x00bar",
	}

	for _, name := range malicious {
		name := name
		t.Run(fmt.Sprintf("name=%q", name), func(t *testing.T) {
			p := newTestPKI(pki.Config{NoPass: true})
			buildTestCA(t, p)

			_, err := p.BuildClientFull(name)
			assert.Error(t, err,
				"BuildClientFull(%q) must be rejected: names containing path separators, "+
					"'..', empty string, or null bytes can escape the PKI directory and "+
					"write to arbitrary filesystem locations", name)
		})
	}
}

// TestMemoryKeyStorage_NoOrphanPairsAfterBuildFull verifies that BuildClientFull
// does not leave orphan key-only pairs in memory storage.
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

	for _, pair := range all {
		assert.NotNil(t, pair.CertPEM,
			"GetAll returned a key-only pair (CertPEM==nil) for name %q; "+
				"intermediate GenReq pairs must not survive after SignReq completes", pair.Name)
	}
}

// --- Renew ---

func TestRenew_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	orig, err := p.BuildClientFull("client1")
	require.NoError(t, err)
	origCert, _ := orig.Certificate()
	origSerial := origCert.SerialNumber

	renewed, err := p.Renew("client1", pki.WithDays(9999))
	require.NoError(t, err)
	assert.Equal(t, "client1", renewed.Name)

	newCert, err := renewed.Certificate()
	require.NoError(t, err)
	assert.NotEqual(t, 0, newCert.SerialNumber.Cmp(origSerial))
	assert.Equal(t, origCert.PublicKey, newCert.PublicKey)
}

// TestRenew_OldCertNoLongerValidAfterRenew verifies that after Renew, the old
// certificate is invalidated in the index.
func TestRenew_OldCertNoLongerValidAfterRenew(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	_, err := p.BuildClientFull("client1", pki.WithDays(1))
	require.NoError(t, err)

	_, err = p.Renew("client1")
	require.NoError(t, err)

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

// TestRenew_OldCertIndexUpdateFailureIsReturned verifies that Renew propagates
// the index.Update failure for the old cert's serial.
func TestRenew_OldCertIndexUpdateFailureIsReturned(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	goodP := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, goodP)
	_, err := goodP.BuildClientFull("client1")
	require.NoError(t, err)

	failIdx := &errUpdateIndexDB{inner: idx, errOnUpdate: errDiskFull}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, failIdx, sp, crl)

	_, err = p.Renew("client1")
	assert.Error(t, err,
		"Renew must propagate the index.Update failure for the old cert's serial; "+
			"silencing it with `_ =` leaves the old cert as StatusValid and returns "+
			"a misleadingly successful result to the caller")
}

// TestRenew_NoCertAccumulationInMemoryStorage verifies that repeated Renew calls
// do not accumulate stale cert pairs in memory storage.
func TestRenew_NoCertAccumulationInMemoryStorage(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, p)

	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err = p.Renew("client1")
		require.NoError(t, err)
	}

	all, err := ks.GetAll()
	require.NoError(t, err)

	assert.Len(t, all, 2,
		"GetAll should return exactly 2 entries (CA + current client1); "+
			"extra entries are stale cert pairs that accumulate in memory after each Renew")
}

// --- ExpireCert ---

func TestExpireCert_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.ExpireCert("client1")
	require.NoError(t, err)
}

func TestExpireCert_NotFound(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	err := p.ExpireCert("notexist")
	assert.Error(t, err)
}

// --- ShowCert ---

func TestShowCert_Found(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	pair, err := p.ShowCert("client1")
	require.NoError(t, err)
	assert.Equal(t, "client1", pair.Name)
}

func TestShowCert_NotFound(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	_, err := p.ShowCert("notexist")
	assert.Error(t, err)
}

// TestShowCert_PathTraversalInName verifies that ShowCert rejects names with
// path traversal.
func TestShowCert_PathTraversalInName(t *testing.T) {
	dir := t.TempDir()
	p, err := pki.NewWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = p.BuildCA()
	require.NoError(t, err)

	_, err = p.ShowCert("../ca")
	assert.Error(t, err,
		"ShowCert('../ca') must return an error; "+
			"without validateEntityName it reads ca.crt via issued/../ca.crt (path traversal)")
}

// --- GenCRL ---

func TestGenCRL_Empty(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	crlPEM, err := p.GenCRL()
	require.NoError(t, err)
	assert.NotEmpty(t, crlPEM)
}

func TestGenCRL_NoCA(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	_, err := p.GenCRL()
	assert.Error(t, err)
}

// TestGenCRL_CorruptCRL verifies that GenCRL returns an error when the
// existing CRL cannot be read, preventing silent CRL number resets.
func TestGenCRL_CorruptCRL(t *testing.T) {
	ks, cs, idx, sp, innerCRL := memory.New()
	badCRL := &errCRLHolder{inner: innerCRL, errOnGet: errors.New("disk error")}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, badCRL)

	buildTestCA(t, p)
	_, err := p.GenCRL()
	assert.Error(t, err)
}

// TestGenCRL_CanRecoverFromCorruptCRLFile verifies that GenCRL or a companion
// method allows recovery from a corrupt CRL without manual filesystem access.
func TestGenCRL_CanRecoverFromCorruptCRLFile(t *testing.T) {
	dir := t.TempDir()
	p, err := pki.NewWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)

	_, err = p.BuildCA()
	require.NoError(t, err)

	_, err = p.GenCRL()
	require.NoError(t, err)

	corruptPath := filepath.Join(dir, "crl.pem")
	require.NoError(t, os.WriteFile(corruptPath, []byte("this is not a valid PEM block"), 0644))

	_, err = p.GenCRL()
	require.Error(t, err, "setup: GenCRL must fail on corrupt crl.pem")

	require.NoError(t, p.ResetCRL(), "ResetCRL must succeed after corrupt crl.pem")

	_, err = p.GenCRL()
	assert.NoError(t, err,
		"GenCRL must succeed after ResetCRL() removes the corrupt crl.pem; "+
			"recovery must be possible through the public API without manual filesystem access")
}

// --- Revoke ---

func TestRevoke_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	pair, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.Revoke("client1", cert.ReasonUnspecified)
	require.NoError(t, err)

	serial, _ := pair.Serial()
	revoked, err := p.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRevoke_NotFound(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	err := p.Revoke("notexist", cert.ReasonUnspecified)
	assert.Error(t, err)
}

func TestRevoke_IndexNotFound(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	errIdx := &errUpdateIndexDB{inner: idx, errOnUpdate: storage.ErrNotFound}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, errIdx, sp, crl)

	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.Revoke("client1", cert.ReasonUnspecified)
	assert.Error(t, err)
}

// TestRevoke_DoesNotUpdateCRLWhenIndexUpdateFails verifies that if index.Update
// fails during Revoke, GenCRL is NOT called and the CRL remains untouched.
func TestRevoke_DoesNotUpdateCRLWhenIndexUpdateFails(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	errIdx := &errUpdateIndexDB{inner: idx, errOnUpdate: errors.New("index: disk full")}
	p := pki.New(pki.Config{NoPass: true}, ks, cs, errIdx, sp, crl)

	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	crlBefore, err := crl.Get()
	require.NoError(t, err)

	revokeErr := p.Revoke("client1", cert.ReasonUnspecified)
	require.Error(t, revokeErr, "Revoke must return an error when index.Update fails")

	crlAfter, err := crl.Get()
	require.NoError(t, err)

	assert.Equal(t, crlBefore.Number, crlAfter.Number,
		"CRL number advanced from %v to %v after a failed Revoke: "+
			"GenCRL must not be called when index.Update returns an error",
		crlBefore.Number, crlAfter.Number)
}

// --- RevokeBySerial ---

func TestRevokeBySerial_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	pair, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	serial, err := pair.Serial()
	require.NoError(t, err)

	err = p.RevokeBySerial(serial, cert.ReasonKeyCompromise)
	require.NoError(t, err)

	revoked, err := p.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// --- RevokeExpired ---

func TestRevokeExpired_NoExpired(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.RevokeExpired("client1", cert.ReasonCessationOfOperation)
	require.NoError(t, err)
}

// TestRevokeExpired_NameVsCNMismatchInOrgMode verifies that RevokeExpired
// works when the storage name differs from the Subject CN.
func TestRevokeExpired_NameVsCNMismatchInOrgMode(t *testing.T) {
	cfg := pki.Config{
		NoPass:       true,
		DNMode:       pki.DNModeOrg,
		SubjTemplate: pkix.Name{Organization: []string{"Acme Corp"}},
	}
	p := newTestPKI(cfg)
	buildTestCA(t, p)

	_, err := p.GenReq("server1")
	require.NoError(t, err)

	_, err = p.SignReq("server1", cert.CertTypeServer,
		pki.WithSubjectOverride(pkix.Name{
			CommonName:   "VPN Server",
			Organization: []string{"Acme Corp"},
		}),
	)
	require.NoError(t, err)

	require.NoError(t, p.ExpireCert("server1"))

	require.NoError(t, p.RevokeExpired("server1", cert.ReasonCessationOfOperation))

	revoked, err := p.ShowRevoked()
	require.NoError(t, err)

	assert.Len(t, revoked, 1,
		"RevokeExpired('server1') should revoke the cert whose storage key is 'server1'; "+
			"IndexFilter.Name matches Subject.CommonName ('VPN Server'), not the storage name")
}

// --- IsRevoked ---

func TestIsRevoked_NotRevoked(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	pair, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	_, err = p.GenCRL()
	require.NoError(t, err)

	serial, _ := pair.Serial()
	revoked, err := p.IsRevoked(serial)
	require.NoError(t, err)
	assert.False(t, revoked)
}

// --- ShowCRL ---

func TestShowCRL_NoCRL(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	crl, err := p.ShowCRL()
	require.NoError(t, err)
	assert.NotNil(t, crl)
}

func TestShowCRL_WithCRL(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.GenCRL()
	require.NoError(t, err)

	crl, err := p.ShowCRL()
	require.NoError(t, err)
	assert.NotNil(t, crl)
}

// --- ShowExpiring ---

func TestShowExpiring_Finds(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1", pki.WithDays(1))
	require.NoError(t, err)

	pairs, err := p.ShowExpiring(2)
	require.NoError(t, err)
	assert.Len(t, pairs, 1)
}

func TestShowExpiring_Misses(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1", pki.WithDays(100))
	require.NoError(t, err)

	pairs, err := p.ShowExpiring(1)
	require.NoError(t, err)
	assert.Empty(t, pairs)
}

// TestShowExpiring_StorageGap verifies that ShowExpiring returns a non-nil
// error when the key storage is missing a cert referenced by the index.
func TestShowExpiring_StorageGap(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)

	buildTestCA(t, p)
	pair, err := p.BuildClientFull("client1", pki.WithDays(1))
	require.NoError(t, err)

	serial, err := pair.Serial()
	require.NoError(t, err)

	// Remove the cert from storage so GetBySerial fails.
	require.NoError(t, ks.DeleteBySerial(serial))

	_, err = p.ShowExpiring(2)
	assert.Error(t, err)
}

// --- ShowRevoked ---

func TestShowRevoked_Empty(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	pairs, err := p.ShowRevoked()
	require.NoError(t, err)
	assert.Empty(t, pairs)
}

func TestShowRevoked_WithRevoked(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.Revoke("client1", cert.ReasonUnspecified)
	require.NoError(t, err)

	pairs, err := p.ShowRevoked()
	require.NoError(t, err)
	assert.Len(t, pairs, 1)
}

// TestShowRevoked_StorageGap verifies that ShowRevoked returns a non-nil
// error when the key storage is missing a revoked cert referenced by the index.
func TestShowRevoked_StorageGap(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)

	buildTestCA(t, p)
	pair, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.Revoke("client1", cert.ReasonUnspecified)
	require.NoError(t, err)

	serial, err := pair.Serial()
	require.NoError(t, err)

	// Remove the cert from storage so GetBySerial fails.
	require.NoError(t, ks.DeleteBySerial(serial))

	_, err = p.ShowRevoked()
	assert.Error(t, err)
}

// --- VerifyCert ---

func TestVerifyCert_Valid(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.VerifyCert("client1")
	require.NoError(t, err)
}

func TestVerifyCert_NotFound(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	err := p.VerifyCert("notexist")
	assert.Error(t, err)
}

func TestVerifyCert_Revoked(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.Revoke("client1", cert.ReasonUnspecified)
	require.NoError(t, err)

	err = p.VerifyCert("client1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

// TestVerifyCert_PathTraversalInName verifies that VerifyCert rejects names
// with path traversal.
func TestVerifyCert_PathTraversalInName(t *testing.T) {
	dir := t.TempDir()
	p, err := pki.NewWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = p.BuildCA()
	require.NoError(t, err)

	err = p.VerifyCert("../ca")
	assert.Error(t, err,
		"VerifyCert('../ca') must return an error; "+
			"without validateEntityName the traversal reads the CA cert")
}

// TestVerifyCert_CRLSignatureIsNotVerified verifies that VerifyCert detects
// when a CRL is signed by a different CA.
func TestVerifyCert_CRLSignatureIsNotVerified(t *testing.T) {
	ks1, cs1, idx1, sp1, crl1 := memory.New()
	p1 := pki.New(pki.Config{NoPass: true}, ks1, cs1, idx1, sp1, crl1)
	buildTestCA(t, p1)

	_, err := p1.BuildClientFull("client1")
	require.NoError(t, err)

	err = p1.Revoke("client1", cert.ReasonUnspecified)
	require.NoError(t, err)

	err = p1.VerifyCert("client1")
	require.Error(t, err, "setup: client1 must be revoked in PKI-1")

	_, cs2, idx2, sp2, crl2 := memory.New()
	ks2, _, _, _, _ := memory.New()
	p2 := pki.New(pki.Config{NoPass: true}, ks2, cs2, idx2, sp2, crl2)
	buildTestCA(t, p2)

	cleanCRLPEM, err := p2.GenCRL()
	require.NoError(t, err)

	// Inject a foreign-CA CRL into PKI-1's CRL holder.
	require.NoError(t, crl1.Put(cleanCRLPEM))

	err = p1.VerifyCert("client1")
	assert.Error(t, err,
		"VerifyCert must call crl.CheckSignatureFrom(caCert); "+
			"a CRL signed by a different CA was silently accepted")
}

// --- UpdateDB ---

func TestUpdateDB_NoExpired(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.UpdateDB()
	require.NoError(t, err)
}

// --- ExportP12 ---

func TestExportP12_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	data, err := p.ExportP12("client1", "password")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestExportP12_EncryptedKey(t *testing.T) {
	// Build with passphrase; export without KeyPassphrase should fail.
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1", pki.WithPassphrase("x"))
	require.NoError(t, err)

	_, err = p.ExportP12("client1", "bundle-pass")
	assert.Error(t, err)

	// With KeyPassphrase set, export should succeed.
	p2 := newTestPKI(pki.Config{NoPass: true, KeyPassphrase: "x"})
	buildTestCA(t, p2)
	_, err = p2.BuildClientFull("client1", pki.WithPassphrase("x"))
	require.NoError(t, err)

	data, err := p2.ExportP12("client1", "bundle-pass")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// --- ExportP7 ---

func TestExportP7_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	data, err := p.ExportP7("client1")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// --- ExportP8 ---

func TestExportP8_NoPassword(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	data, err := p.ExportP8("client1", "")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestExportP8_WithPassword(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	data, err := p.ExportP8("client1", "secret")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// --- ExportP1 ---

func TestExportP1_RSA(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	data, err := p.ExportP1("client1")
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestExportP1_ECDSA_Error(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true, KeyAlgo: pki.AlgoECDSA})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	_, err = p.ExportP1("client1")
	assert.Error(t, err)
}

// --- GenDH ---

func TestGenDH_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{})
	data, err := p.GenDH(128)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "DH PARAMETERS")
}

// --- SetPass ---

func TestSetPass_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.SetPass("client1", "", "newpassword")
	require.NoError(t, err)
}

func TestSetPass_ChangeBack(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)
	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	err = p.SetPass("client1", "", "newpassword")
	require.NoError(t, err)

	err = p.SetPass("client1", "newpassword", "")
	require.NoError(t, err)
}

// TestSetPass_NoCertAccumulationInMemoryStorage verifies that multiple SetPass
// calls do not accumulate duplicate cert pairs in memory storage.
func TestSetPass_NoCertAccumulationInMemoryStorage(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	p := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	buildTestCA(t, p)

	_, err := p.BuildClientFull("client1")
	require.NoError(t, err)

	require.NoError(t, p.SetPass("client1", "", "pass1"))
	require.NoError(t, p.SetPass("client1", "pass1", "pass2"))
	require.NoError(t, p.SetPass("client1", "pass2", ""))

	all, err := ks.GetAll()
	require.NoError(t, err)

	assert.Len(t, all, 2,
		"GetAll should return exactly 2 entries (CA + client1) after SetPass calls; "+
			"extra entries are duplicate cert pairs appended on each passphrase change")
}

// --- Config ---

// TestConfig_DefaultUsesRandomSerials verifies that Config{} defaults to
// random 128-bit serials, not sequential.
func TestConfig_DefaultUsesRandomSerials(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	pair1, err := p.BuildClientFull("c1")
	require.NoError(t, err)
	pair2, err := p.BuildClientFull("c2")
	require.NoError(t, err)

	s1, err := pair1.Serial()
	require.NoError(t, err)
	s2, err := pair2.Serial()
	require.NoError(t, err)

	diff := new(big.Int).Abs(new(big.Int).Sub(s2, s1))
	assert.NotEqual(t, big.NewInt(1), diff,
		"Config{} is documented to default to RandomSerial=true (128-bit random serials); "+
			"sequential serials (diff=1) prove RandomSerial defaults to false")
}

// TestConfig_RandomSerialFalseIsRespected verifies that Config{SequentialSerial: true}
// produces sequential serials from SerialProvider.
func TestConfig_RandomSerialFalseIsRespected(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	cfg := pki.Config{NoPass: true, SequentialSerial: true}
	p := pki.New(cfg, ks, cs, idx, sp, crl)

	buildTestCA(t, p)

	pair1, err := p.BuildClientFull("c1")
	require.NoError(t, err)
	pair2, err := p.BuildClientFull("c2")
	require.NoError(t, err)

	s1, err := pair1.Serial()
	require.NoError(t, err)
	s2, err := pair2.Serial()
	require.NoError(t, err)

	diff := new(big.Int).Sub(s2, s1)
	assert.Equal(t, big.NewInt(1), diff,
		"Config{SequentialSerial: true} must use sequential serials from SerialProvider "+
			"(s2 = s1+1); got s1=%s s2=%s diff=%s",
		s1.Text(16), s2.Text(16), diff.Text(16))
}

// TestConfig_PassphrasesNotLeakedInStringFormatting verifies that formatting a
// Config struct does not leak passphrase values.
func TestConfig_PassphrasesNotLeakedInStringFormatting(t *testing.T) {
	const caPass = "super-secret-ca-passphrase"
	const keyPass = "super-secret-key-passphrase"

	cfg := pki.Config{
		CAPassphrase:  caPass,
		KeyPassphrase: keyPass,
	}

	formatted := fmt.Sprintf("%+v", cfg)

	assert.False(t, strings.Contains(formatted, caPass),
		"CAPassphrase %q is visible in %%+v output of Config", caPass)

	assert.False(t, strings.Contains(formatted, keyPass),
		"KeyPassphrase %q is visible in %%+v output of Config", keyPass)
}

// --- CertType ---

// TestCertType_UnrecognizedEKUIsNotSilentlyClient verifies that CertType()
// returns an error for a cert whose EKU is not Server or Client auth.
func TestCertType_UnrecognizedEKUIsNotSilentlyClient(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	pair, err := p.BuildClientFull("codesign",
		pki.WithCertModifier(func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}),
	)
	require.NoError(t, err)

	certType, err := pair.CertType()
	if err == nil {
		assert.NotEqual(t, cert.CertTypeClient, certType,
			"cert with only CodeSigning EKU was silently misclassified as CertTypeClient; "+
				"CertType() must return an error for unrecognised EKU combinations")
	}
	assert.Error(t, err,
		"CertType() must return an error for a cert with an unrecognised EKU (CodeSigning), "+
			"not silently fall through to CertTypeClient")
}
