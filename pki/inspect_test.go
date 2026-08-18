package pki_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func TestShowReq(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	csrPEM, err := pk.GenReq("alice", pki.WithDNSNames("alice.example.test"))
	require.NoError(t, err)
	original := append([]byte(nil), csrPEM...)

	got, err := pk.ShowReq("alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Name)
	assert.Equal(t, original, got.CSRPEM)
	request, err := got.Request()
	require.NoError(t, err)
	assert.Equal(t, "alice", request.Subject.CommonName)
	assert.Equal(t, []string{"alice.example.test"}, request.DNSNames)

	got.CSRPEM[0] ^= 0xff
	again, err := pk.ShowReq("alice")
	require.NoError(t, err)
	assert.Equal(t, original, again.CSRPEM)
}

func TestShowReqAcceptsDamagedSignature(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	csrPEM, err := pk.GenReq("alice")
	require.NoError(t, err)
	require.NoError(t, cs.PutCSR("alice", corruptCSRSignature(t, csrPEM)))

	got, err := pk.ShowReq("alice")
	require.NoError(t, err)
	request, err := got.Request()
	require.NoError(t, err)
	assert.Error(t, request.CheckSignature())
}

func TestGenReqUsesEasyRSADefaultECDSASignatureAlgorithm(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			pk := newTestPKI(pki.Config{NoPass: true, KeyAlgo: pki.AlgoECDSA, Curve: curve})
			_, err := pk.GenReq("alice")
			require.NoError(t, err)
			request, err := pk.ShowReq("alice")
			require.NoError(t, err)
			parsed, err := request.Request()
			require.NoError(t, err)
			assert.Equal(t, x509.ECDSAWithSHA256, parsed.SignatureAlgorithm)
		})
	}
}

func TestShowReqErrors(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)

	_, err := pk.ShowReq("../escape")
	assert.Error(t, err)

	_, err = pk.ShowReq("missing")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	require.NoError(t, cs.PutCSR("broken", []byte("not a csr")))
	_, err = pk.ShowReq("broken")
	assert.Error(t, err)
}

func TestShowEKU(t *testing.T) {
	pk := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, pk)

	tests := []struct {
		name  string
		usage []x509.ExtKeyUsage
		want  certpkg.EKUType
	}{
		{name: "client", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, want: certpkg.EKUClient},
		{name: "server", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, want: certpkg.EKUServer},
		{name: "server-client", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, want: certpkg.EKUServerClient},
		{name: "code-signing", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, want: certpkg.EKUCodeSigning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pk.BuildClientFull(tt.name, pki.WithCertModifier(func(c *x509.Certificate) {
				c.ExtKeyUsage = append([]x509.ExtKeyUsage(nil), tt.usage...)
			}))
			require.NoError(t, err)
			got, err := pk.ShowEKU(tt.name)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestShowEKUUnknownAndUndefined(t *testing.T) {
	pk := newTestPKI(pki.Config{NoPass: true})
	buildTestCA(t, pk)

	_, err := pk.BuildClientFull("undefined", pki.WithCertModifier(func(c *x509.Certificate) {
		c.ExtKeyUsage = nil
	}))
	require.NoError(t, err)
	got, err := pk.ShowEKU("undefined")
	assert.Equal(t, certpkg.EKUUndefined, got)
	assert.ErrorIs(t, err, certpkg.ErrUnknownEKU)

	_, err = pk.BuildClientFull("unknown", pki.WithCertModifier(func(c *x509.Certificate) {
		c.ExtKeyUsage = nil
		c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	}))
	require.NoError(t, err)
	got, err = pk.ShowEKU("unknown")
	assert.Equal(t, certpkg.EKUUnknown, got)
	assert.ErrorIs(t, err, certpkg.ErrUnknownEKU)
}

func TestCheckSerialAcrossStatuses(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	entries := []storage.IndexEntry{
		{Status: storage.StatusValid, Serial: big.NewInt(1), Subject: pkix.Name{CommonName: "valid"}},
		{Status: storage.StatusExpired, Serial: big.NewInt(2), Subject: pkix.Name{CommonName: "expired"}},
		{Status: storage.StatusRevoked, Serial: big.NewInt(3), Subject: pkix.Name{CommonName: "revoked"}, RevokedAt: time.Now()},
	}
	for _, entry := range entries {
		require.NoError(t, idx.Record(entry))
	}

	for _, want := range entries {
		got, err := pk.CheckSerial(want.Serial)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, want.Status, got.Status)
		assert.Equal(t, want.Subject.CommonName, got.Subject.CommonName)
	}

	got, err := pk.CheckSerial(big.NewInt(0))
	require.NoError(t, err)
	assert.Nil(t, got)
	got, err = pk.CheckSerial(big.NewInt(999))
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestCheckSerialReturnsDeepCopy(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	oid := asn1.ObjectIdentifier{1, 2, 3, 4}
	nestedBytes := []byte{4, 5, 6}
	nested := map[string]any{
		"matrix":  [][]byte{{7, 8, 9}},
		"pointer": &nestedBytes,
	}
	overlapBuffer := []byte{10, 11, 12}
	overlap := overlappingSlices{Short: overlapBuffer[:1], Long: overlapBuffer[:2]}
	entry := storage.IndexEntry{
		Status: storage.StatusValid,
		Serial: big.NewInt(42),
		Subject: pkix.Name{
			Country:       []string{"US"},
			Organization:  []string{"Example"},
			StreetAddress: []string{"Main Street"},
			Names: []pkix.AttributeTypeAndValue{{
				Type:  append(asn1.ObjectIdentifier(nil), oid...),
				Value: []byte{1, 2, 3},
			}},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  append(asn1.ObjectIdentifier(nil), oid...),
					Value: asn1.ObjectIdentifier{9, 8, 7},
				},
				{
					Type:  asn1.ObjectIdentifier{1, 2, 3, 5},
					Value: nested,
				},
				{
					Type:  asn1.ObjectIdentifier{1, 2, 3, 7},
					Value: overlap,
				},
			},
		},
	}
	require.NoError(t, idx.Record(entry))

	got, err := pk.CheckSerial(big.NewInt(42))
	require.NoError(t, err)
	require.NotNil(t, got)
	got.Serial.SetInt64(99)
	got.Subject.Country[0] = "GB"
	got.Subject.Organization[0] = "Changed"
	got.Subject.StreetAddress[0] = "Changed"
	got.Subject.Names[0].Type[0] = 99
	got.Subject.Names[0].Value.([]byte)[0] = 99
	got.Subject.ExtraNames[0].Type[0] = 99
	got.Subject.ExtraNames[0].Value.(asn1.ObjectIdentifier)[0] = 99
	gotNested := got.Subject.ExtraNames[1].Value.(map[string]any)
	gotNested["matrix"].([][]byte)[0][0] = 99
	(*gotNested["pointer"].(*[]byte))[0] = 99
	gotOverlap := got.Subject.ExtraNames[2].Value.(overlappingSlices)
	require.Len(t, gotOverlap.Short, 1)
	require.Len(t, gotOverlap.Long, 2)
	assert.Equal(t, 3, cap(gotOverlap.Short))
	assert.Equal(t, 3, cap(gotOverlap.Long))
	gotOverlap.Short[0] = 99

	again, err := pk.CheckSerial(big.NewInt(42))
	require.NoError(t, err)
	require.NotNil(t, again)
	assert.Equal(t, int64(42), again.Serial.Int64())
	assert.Equal(t, []string{"US"}, again.Subject.Country)
	assert.Equal(t, []string{"Example"}, again.Subject.Organization)
	assert.Equal(t, []string{"Main Street"}, again.Subject.StreetAddress)
	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 3, 4}, again.Subject.Names[0].Type)
	assert.Equal(t, []byte{1, 2, 3}, again.Subject.Names[0].Value)
	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 3, 4}, again.Subject.ExtraNames[0].Type)
	assert.Equal(t, asn1.ObjectIdentifier{9, 8, 7}, again.Subject.ExtraNames[0].Value)
	againNested := again.Subject.ExtraNames[1].Value.(map[string]any)
	assert.Equal(t, byte(7), againNested["matrix"].([][]byte)[0][0])
	assert.Equal(t, byte(4), (*againNested["pointer"].(*[]byte))[0])
	againOverlap := again.Subject.ExtraNames[2].Value.(overlappingSlices)
	assert.Equal(t, []byte{10}, againOverlap.Short)
	assert.Equal(t, []byte{10, 11}, againOverlap.Long)
}

type overlappingSlices struct {
	Short []byte
	Long  []byte
}

func TestCheckSerialRejectsMutableUnexportedAttributeState(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	entry := storage.IndexEntry{
		Status: storage.StatusValid,
		Serial: big.NewInt(43),
		Subject: pkix.Name{Names: []pkix.AttributeTypeAndValue{{
			Type:  asn1.ObjectIdentifier{1, 2, 3, 6},
			Value: mutableUnexportedAttribute{values: map[string]string{"key": "value"}},
		}}},
	}
	require.NoError(t, idx.Record(entry))

	_, err := pk.CheckSerial(big.NewInt(43))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot clone mutable unexported field")
}

type mutableUnexportedAttribute struct {
	values map[string]string
}

func TestCheckSerialErrors(t *testing.T) {
	ks, cs, idx, sp, crl := memory.New()
	pk := mustNewPKI(t, pki.Config{NoPass: true}, ks, cs, idx, sp, crl)

	_, err := pk.CheckSerial(nil)
	assert.Error(t, err)
	_, err = pk.CheckSerial(big.NewInt(-1))
	assert.Error(t, err)

	duplicate := storage.IndexEntry{Status: storage.StatusValid, Serial: big.NewInt(7)}
	dupIndex := &queryOverrideIndex{IndexDB: idx, entries: []storage.IndexEntry{duplicate, duplicate}}
	dupPKI := mustNewPKI(t, pki.Config{}, ks, cs, dupIndex, sp, crl)
	_, err = dupPKI.CheckSerial(big.NewInt(7))
	assert.Error(t, err)
}

func TestCheckSerialPropagatesMalformedFilesystemIndex(t *testing.T) {
	dir := t.TempDir()
	_, err := pki.NewWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), []byte("not an index line\n"), 0o600))
	pk, err := pki.OpenWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)

	_, err = pk.CheckSerial(big.NewInt(1))
	assert.Error(t, err)
}

func TestOpenWithFSDoesNotInitializeMissingOrEmptyPath(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing")
		_, err := pki.OpenWithFS(dir, pki.Config{})
		require.NoError(t, err)
		_, err = os.Stat(dir)
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		before := snapshotTestTree(t, dir)
		_, err := pki.OpenWithFS(dir, pki.Config{})
		require.NoError(t, err)
		assert.Equal(t, before, snapshotTestTree(t, dir))
	})
}

func TestOpenWithFSReadsWithoutMutatingValidPKI(t *testing.T) {
	dir := t.TempDir()
	writer, err := pki.NewWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = writer.BuildCA()
	require.NoError(t, err)
	before := snapshotTestTree(t, dir)

	reader, err := pki.OpenWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)
	_, err = reader.ShowCA()
	require.NoError(t, err)
	assert.Equal(t, before, snapshotTestTree(t, dir))
}

func TestOpenWithFSRejectsForeignLayout(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "foreign.txt"), []byte("foreign"), 0o600))
	_, err := pki.OpenWithFS(dir, pki.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not look like the current PKI filesystem layout")
}

func TestNewWithFSStillInitializesLayout(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	_, err := pki.NewWithFS(dir, pki.Config{})
	require.NoError(t, err)
	for _, subdir := range []string{"private", "issued", "reqs", "certs_by_serial"} {
		assert.DirExists(t, filepath.Join(dir, subdir))
	}
}

type queryOverrideIndex struct {
	storage.IndexDB
	entries []storage.IndexEntry
}

func (db *queryOverrideIndex) Query(storage.IndexFilter) ([]storage.IndexEntry, error) {
	return db.entries, nil
}

type testTreeEntry struct {
	Mode fs.FileMode
	Data string
	Link string
}

func snapshotTestTree(t *testing.T, root string) map[string]testTreeEntry {
	t.Helper()
	result := make(map[string]testTreeEntry)
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := testTreeEntry{Mode: info.Mode()}
		switch {
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.Data = string(data)
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			item.Link = link
		}
		result[rel] = item
		return nil
	}))
	return result
}
