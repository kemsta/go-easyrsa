package pki_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
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

func (e *errUpdateIndexDB) Query(filter storage.IndexFilter) ([]storage.IndexEntry, error) {
	return e.inner.Query(filter)
}

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

// --- GenReq / ImportReq / SignReq ---

func TestGenReq_Basic(t *testing.T) {
	p := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, p)

	csrPEM, err := p.GenReq("client1")
	require.NoError(t, err)
	assert.NotEmpty(t, csrPEM)
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
