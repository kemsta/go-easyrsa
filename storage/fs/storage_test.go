package fs_test

import (
	"crypto/x509/pkix"
	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	fs "github.com/kemsta/go-easyrsa/v2/storage/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- SerialProvider ---

// TestSerialProvider_Concurrent verifies that 20 goroutines calling Next()
// in parallel all receive unique serial numbers (no duplicate allocations).
func TestSerialProvider_Concurrent(t *testing.T) {
	dir := t.TempDir()
	sp := fs.NewSerialProvider(dir)

	const n = 20
	serials := make([]*big.Int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			s, err := sp.Next()
			if err != nil {
				t.Errorf("Next() error: %v", err)
				return
			}
			serials[i] = s
		}()
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for _, s := range serials {
		if s == nil {
			continue
		}
		key := s.Text(16)
		if seen[key] {
			t.Errorf("duplicate serial %s", key)
		}
		seen[key] = true
	}
}

// TestSerialProvider_CorruptFileReturnsError verifies that Next() returns an
// error when the serial file is corrupt or contains an invalid serial.
func TestSerialProvider_CorruptFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	serialPath := filepath.Join(dir, "serial")

	cases := []struct {
		name    string
		content []byte
	}{
		{"empty file", []byte{}},
		{"whitespace only", []byte("   \n")},
		{"non-hex content", []byte("not-a-hex-number\n")},
		{"zero serial", []byte("00\n")},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(serialPath, tc.content, 0644))

			sp := fs.NewSerialProvider(dir)
			n, err := sp.Next()

			if err == nil {
				assert.True(t, n != nil && n.Sign() > 0,
					"SerialProvider.Next() with corrupt file %q returned serial %v (non-positive); "+
						"serial 0 is invalid per RFC 5280 § 4.1.2.2.", tc.name, n)
			}
			assert.Error(t, err,
				"SerialProvider.Next() must return an error for corrupt serial file (%s: %q)",
				tc.name, string(tc.content))
		})
	}
}

// --- IndexDB ---

// TestIndexDB_WriteAll_Idempotent records entries, updates one, and queries to
// confirm the temp+rename write path produces a correct result.
func TestIndexDB_WriteAll_Idempotent(t *testing.T) {
	dir := t.TempDir()
	db := fs.NewIndexDB(dir)
	sp := fs.NewSerialProvider(dir)

	s1, _ := sp.Next()
	s2, _ := sp.Next()
	s3, _ := sp.Next()

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.AddDate(1, 0, 0)

	for _, s := range []*big.Int{s1, s2, s3} {
		e := storage.IndexEntry{Status: storage.StatusValid, Serial: s, ExpiresAt: expires}
		if err := db.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	// Update s2 to revoked.
	if err := db.Update(s2, storage.StatusRevoked, now, 0); err != nil {
		t.Fatalf("Update: %v", err)
	}

	revokedStatus := storage.StatusRevoked
	results, err := db.Query(storage.IndexFilter{Status: &revokedStatus})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 || results[0].Serial.Cmp(s2) != 0 {
		t.Errorf("expected 1 revoked entry with serial %s, got %v", s2.Text(16), results)
	}
}

// TestParseIndexLine_InvalidSerial writes a line with an invalid hex serial
// directly to index.txt and verifies that Query returns an error.
func TestParseIndexLine_InvalidSerial(t *testing.T) {
	dir := t.TempDir()
	db := fs.NewIndexDB(dir)

	badLine := "V\t310101000000Z\t\tZZZZNOTHEX\tunknown\t/CN=bad\n"
	if err := os.WriteFile(filepath.Join(dir, "index.txt"), []byte(badLine), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := db.Query(storage.IndexFilter{})
	if err == nil {
		t.Errorf("Query must return an error when index.txt contains a malformed serial; " +
			"silently skipping corrupt lines makes revoked certs invisible to callers")
	}
}

// TestIndexDB_ConcurrentUpdate_AllUpdatesApplied verifies that concurrent
// Update calls are properly serialized and none are lost.
func TestIndexDB_ConcurrentUpdate_AllUpdatesApplied(t *testing.T) {
	dir := t.TempDir()
	db := fs.NewIndexDB(dir)
	sp := fs.NewSerialProvider(dir)

	const N = 20
	serials := make([]*big.Int, N)
	expires := time.Now().Add(24 * time.Hour)

	for i := 0; i < N; i++ {
		s, err := sp.Next()
		require.NoError(t, err)
		serials[i] = s
		require.NoError(t, db.Record(storage.IndexEntry{
			Status:    storage.StatusValid,
			Serial:    s,
			ExpiresAt: expires,
		}))
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(N)
	now := time.Now()
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			_ = db.Update(serials[i], storage.StatusRevoked, now, 0)
		}()
	}
	close(start)
	wg.Wait()

	revokedStatus := storage.StatusRevoked
	results, err := db.Query(storage.IndexFilter{Status: &revokedStatus})
	require.NoError(t, err)
	assert.Len(t, results, N,
		"all %d concurrent Updates must be persisted; "+
			"fewer entries means the TOCTOU race in IndexDB.Update caused lost writes", N)
}

// TestIndexDB_Query_MalformedLineReturnsError verifies that Query returns an
// error when index.txt contains a malformed line.
func TestIndexDB_Query_MalformedLineReturnsError(t *testing.T) {
	dir := t.TempDir()
	db := fs.NewIndexDB(dir)
	sp := fs.NewSerialProvider(dir)

	s, err := sp.Next()
	require.NoError(t, err)
	require.NoError(t, db.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    s,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	indexPath := filepath.Join(dir, "index.txt")
	existing, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	corrupt := append(existing, []byte("this-is-not-a-valid-index-line\n")...)
	require.NoError(t, os.WriteFile(indexPath, corrupt, 0644))

	_, err = db.Query(storage.IndexFilter{})
	assert.Error(t, err,
		"IndexDB.Query must return an error when index.txt contains a malformed line")
}

// TestIndexDB_Query_CorruptRevocationLineHidesRevokedCert verifies that a
// corrupt revocation line causes an error rather than silently hiding the entry.
func TestIndexDB_Query_CorruptRevocationLineHidesRevokedCert(t *testing.T) {
	dir := t.TempDir()
	db := fs.NewIndexDB(dir)
	sp := fs.NewSerialProvider(dir)

	s1, err := sp.Next()
	require.NoError(t, err)
	require.NoError(t, db.Record(storage.IndexEntry{
		Status:    storage.StatusValid,
		Serial:    s1,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))

	s2, err := sp.Next()
	require.NoError(t, err)
	require.NoError(t, db.Record(storage.IndexEntry{
		Status:    storage.StatusRevoked,
		Serial:    s2,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}))
	require.NoError(t, db.Update(s2, storage.StatusRevoked, time.Now(), 0))

	revokedStatus := storage.StatusRevoked
	entries, err := db.Query(storage.IndexFilter{Status: &revokedStatus})
	require.NoError(t, err)
	require.Len(t, entries, 1, "setup: revoked entry must be visible before corruption")

	indexPath := filepath.Join(dir, "index.txt")
	existing, err := os.ReadFile(indexPath)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimRight(string(existing), "\n"), "\n")
	require.Len(t, lines, 2, "setup: index.txt must have exactly 2 lines")

	corrupted := lines[0] + "\nCORRUPT-REVOKED-LINE-MALFORMED\n"
	require.NoError(t, os.WriteFile(indexPath, []byte(corrupted), 0644))

	entries, err = db.Query(storage.IndexFilter{Status: &revokedStatus})
	if err != nil {
		return // acceptable: error surfaced
	}
	assert.Len(t, entries, 1,
		"revoked certificate (serial %s) became invisible after its index line was corrupted",
		s2.Text(16))
}

// --- CRLHolder ---

// TestCRLHolder_Get_CorruptPEMReturnsError verifies that Get returns an error
// when crl.pem contains invalid PEM data.
func TestCRLHolder_Get_CorruptPEMReturnsError(t *testing.T) {
	dir := t.TempDir()

	corrupt := []byte("this is not a valid PEM block — file was truncated mid-write")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "crl.pem"), corrupt, 0644))

	ch := fs.NewCRLHolder(dir)
	_, err := ch.Get()
	assert.Error(t, err,
		"Get() on a corrupt crl.pem must return an error; "+
			"returning an empty RevocationList allows revoked certs to appear valid")
}

// --- KeyStorage ---

// TestKeyStorage_HasMutex verifies that fs.KeyStorage has a sync.Mutex or
// sync.RWMutex field so that concurrent Puts are serialized.
func TestKeyStorage_HasMutex(t *testing.T) {
	ks := fs.NewKeyStorage(t.TempDir(), "ca")
	typ := reflect.TypeOf(ks).Elem()

	mutexType := reflect.TypeOf(sync.Mutex{})
	rwMutexType := reflect.TypeOf(sync.RWMutex{})

	for i := 0; i < typ.NumField(); i++ {
		ft := typ.Field(i).Type
		if ft == mutexType || ft == rwMutexType {
			return // mutex found
		}
	}

	t.Errorf(
		"fs.KeyStorage has no sync.Mutex or sync.RWMutex field (fields: %s); "+
			"concurrent Put calls can interleave cert and key writes",
		func() string {
			var names []string
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				names = append(names, f.Name+":"+f.Type.String())
			}
			return strings.Join(names, ", ")
		}(),
	)
}

// TestKeyStorage_GetBySerial_ReturnsStorageName_NotCN verifies that GetBySerial
// returns the storage entity name, not the Subject CN.
func TestKeyStorage_GetBySerial_ReturnsStorageName_NotCN(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, fs.InitDirs(dir))

	p, err := pki.NewWithFS(dir, pki.Config{
		NoPass:       true,
		DNMode:       pki.DNModeOrg,
		SubjTemplate: pkix.Name{Organization: []string{"Acme Corp"}},
	})
	require.NoError(t, err)
	_, err = p.BuildCA()
	require.NoError(t, err)

	_, err = p.GenReq("server1")
	require.NoError(t, err)
	pair, err := p.SignReq("server1", cert.CertTypeServer,
		pki.WithSubjectOverride(pkix.Name{
			CommonName:   "VPN Server",
			Organization: []string{"Acme Corp"},
		}),
	)
	require.NoError(t, err)

	serial, err := pair.Serial()
	require.NoError(t, err)

	ks := fs.NewKeyStorage(dir, "ca")
	got, err := ks.GetBySerial(serial)
	require.NoError(t, err)

	assert.Equal(t, "server1", got.Name,
		"GetBySerial must return the storage entity name ('server1'), not the Subject CN ('VPN Server')")
}
func newFSPKI(t *testing.T) (string, *pki.PKI) {
	t.Helper()
	dir := t.TempDir()
	pk, err := pki.NewWithFS(dir, pki.Config{NoPass: true, SequentialSerial: true})
	require.NoError(t, err)
	return dir, pk
}

func mustSerial(t *testing.T, pair *cert.Pair) *big.Int {
	t.Helper()
	serial, err := pair.Serial()
	require.NoError(t, err)
	return new(big.Int).Set(serial)
}

func collectExportedPairs(t *testing.T, exporter storage.PairExporter) []*cert.Pair {
	t.Helper()
	var pairs []*cert.Pair
	err := exporter.ExportPairs(func(pair *cert.Pair) error {
		cp := &cert.Pair{Name: pair.Name}
		if pair.CertPEM != nil {
			cp.CertPEM = append([]byte(nil), pair.CertPEM...)
		}
		if pair.KeyPEM != nil {
			cp.KeyPEM = append([]byte(nil), pair.KeyPEM...)
		}
		pairs = append(pairs, cp)
		return nil
	})
	require.NoError(t, err)
	return pairs
}

func pairIDs(t *testing.T, pairs []*cert.Pair) []string {
	t.Helper()
	ids := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		serial, err := pair.Serial()
		require.NoError(t, err)
		ids = append(ids, pair.Name+":"+storage.HexSerial(serial))
	}
	sort.Strings(ids)
	return ids
}
func TestKeyStorage_PublicCRUDAndDeleteSemantics(t *testing.T) {
	dir, pk := newFSPKI(t)
	_, err := pk.BuildCA()
	require.NoError(t, err)
	client1, err := pk.BuildClientFull("client1")
	require.NoError(t, err)
	client2, err := pk.BuildClientFull("client2")
	require.NoError(t, err)

	ks := fs.NewKeyStorage(dir, "ca")

	pairs, err := ks.GetByName("client1")
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	assert.Equal(t, "client1", pairs[0].Name)

	last, err := ks.GetLastByName("client1")
	require.NoError(t, err)
	assert.Equal(t, "client1", last.Name)

	bySerial, err := ks.GetBySerial(mustSerial(t, client1))
	require.NoError(t, err)
	assert.Equal(t, "client1", bySerial.Name)

	all, err := ks.GetAll()
	require.NoError(t, err)
	require.Len(t, all, 3)
	assert.ElementsMatch(t, []string{"ca", "client1", "client2"}, []string{all[0].Name, all[1].Name, all[2].Name})

	serial2 := mustSerial(t, client2)
	serialHex2 := storage.HexSerial(serial2)
	require.NoError(t, ks.DeleteBySerial(serial2))
	_, err = ks.GetBySerial(serial2)
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = os.Stat(filepath.Join(dir, "certs_by_serial", serialHex2+".pem"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, "certs_by_serial", serialHex2+".name"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = ks.GetLastByName("client2")
	require.NoError(t, err, "DeleteBySerial must not remove the named certificate view")

	serial1 := mustSerial(t, client1)
	require.NoError(t, ks.DeleteByName("client1"))
	_, err = ks.GetByName("client1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = ks.GetBySerial(serial1)
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = os.Stat(filepath.Join(dir, "issued", "client1.crt"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, "private", "client1.key"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestKeyStorage_GetLastByNameFallsBackToRevokedStorage(t *testing.T) {
	dir, pk := newFSPKI(t)
	_, err := pk.BuildCA()
	require.NoError(t, err)
	client, err := pk.BuildClientFull("client1")
	require.NoError(t, err)
	require.NoError(t, pk.Revoke("client1", cert.ReasonKeyCompromise))

	ks := fs.NewKeyStorage(dir, "ca")
	pair, err := ks.GetLastByName("client1")
	require.NoError(t, err)
	assert.Equal(t, "client1", pair.Name)
	assert.NotEmpty(t, pair.CertPEM)
	assert.NotEmpty(t, pair.KeyPEM)
	assert.Zero(t, mustSerial(t, pair).Cmp(mustSerial(t, client)))
}

func TestKeyStorage_CleanOrphansRemovesUnknownCertArtifacts(t *testing.T) {
	dir, pk := newFSPKI(t)
	caPair, err := pk.BuildCA()
	require.NoError(t, err)
	client1, err := pk.BuildClientFull("client1")
	require.NoError(t, err)
	client2, err := pk.BuildClientFull("client2")
	require.NoError(t, err)

	knownSerials := map[string]bool{
		storage.HexSerial(mustSerial(t, caPair)):  true,
		storage.HexSerial(mustSerial(t, client1)): true,
	}

	ks := fs.NewKeyStorage(dir, "ca")
	require.NoError(t, ks.CleanOrphans(knownSerials))

	serialHex2 := storage.HexSerial(mustSerial(t, client2))
	_, err = os.Stat(filepath.Join(dir, "certs_by_serial", serialHex2+".pem"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, "certs_by_serial", serialHex2+".name"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, "issued", "client2.crt"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(dir, "private", "client2.key"))
	require.NoError(t, err, "CleanOrphans must preserve private keys because they may be shared with a valid renewal")

	_, err = ks.GetBySerial(mustSerial(t, client1))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
}

func TestCSRStorage_PublicCRUD(t *testing.T) {
	dir, _ := newFSPKI(t)
	cs := fs.NewCSRStorage(dir)

	require.NoError(t, cs.PutCSR("client1", []byte("csr-1")))
	require.NoError(t, cs.PutCSR("client2", []byte("csr-2")))

	csr, err := cs.GetCSR("client1")
	require.NoError(t, err)
	assert.Equal(t, []byte("csr-1"), csr)

	names, err := cs.ListCSRs()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"client1", "client2"}, names)

	require.NoError(t, cs.DeleteCSR("client1"))
	_, err = cs.GetCSR("client1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	assert.ErrorIs(t, cs.DeleteCSR("client1"), storage.ErrNotFound)
}

func TestSerialProvider_SetNextPersistsAcrossInstances(t *testing.T) {
	dir, _ := newFSPKI(t)
	sp := fs.NewSerialProvider(dir)

	assert.Error(t, sp.SetNext(nil))
	assert.Error(t, sp.SetNext(big.NewInt(0)))

	require.NoError(t, sp.SetNext(big.NewInt(42)))
	next, err := sp.Next()
	require.NoError(t, err)
	assert.Zero(t, next.Cmp(big.NewInt(42)))

	sp2 := fs.NewSerialProvider(dir)
	next, err = sp2.Next()
	require.NoError(t, err)
	assert.Zero(t, next.Cmp(big.NewInt(43)))
}

func TestCRLHolder_PublicBehavior(t *testing.T) {
	dir, pk := newFSPKI(t)
	ch := fs.NewCRLHolder(dir)

	list, err := ch.Get()
	require.NoError(t, err)
	assert.Empty(t, list.RevokedCertificateEntries)

	_, err = pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("client1")
	require.NoError(t, err)
	require.NoError(t, pk.Revoke("client1", cert.ReasonKeyCompromise))
	crlPEM, err := pk.GenCRL()
	require.NoError(t, err)

	require.NoError(t, ch.Put(crlPEM))
	list, err = ch.Get()
	require.NoError(t, err)
	require.Len(t, list.RevokedCertificateEntries, 1)

	require.NoError(t, ch.Delete())
	list, err = ch.Get()
	require.NoError(t, err)
	assert.Empty(t, list.RevokedCertificateEntries)
}
