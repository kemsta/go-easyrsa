package main

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestCLIAndDirectPKIProduceEquivalentLifecycleStateShape(t *testing.T) {
	t.Setenv("EASYRSA_RAND_SN", "no")
	directDir := filepath.Join(t.TempDir(), "direct")
	cliDir := filepath.Join(t.TempDir(), "cli")

	direct, err := pki.OpenWithFS(directDir, pki.Config{
		NoPass:           true,
		SequentialSerial: true,
		KeyAlgo:          pki.AlgoRSA,
		KeySize:          1024,
	})
	require.NoError(t, err)
	require.NoError(t, direct.InitPKI(pki.InitPKIOptions{}))
	_, err = direct.BuildCA(pki.WithCN("Easy-RSA CA"))
	require.NoError(t, err)
	_, err = direct.BuildClientFull("alice")
	require.NoError(t, err)
	_, err = direct.Renew("alice")
	require.NoError(t, err)
	_, err = direct.BuildClientFull("bob")
	require.NoError(t, err)
	require.NoError(t, direct.RevokeIssued("bob", cert.ReasonUnspecified))
	_, err = direct.GenCRL()
	require.NoError(t, err)

	commands := [][]string{
		{"--pki-dir", cliDir, "init-pki"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-ca"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-client-full", "alice"},
		{"--pki-dir", cliDir, "renew", "alice"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-client-full", "bob"},
		{"--pki-dir", cliDir, "revoke-issued", "bob"},
		{"--pki-dir", cliDir, "gen-crl"},
	}
	for _, arguments := range commands {
		output, err := runCLI(t, arguments...)
		require.NoError(t, err, "%v: %s", arguments, output)
	}
	cliPKI, err := pki.OpenWithFS(cliDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)

	directSnapshot, err := direct.ExportSnapshot()
	require.NoError(t, err)
	cliSnapshot, err := cliPKI.ExportSnapshot()
	require.NoError(t, err)
	require.Equal(t, snapshotShape(directSnapshot), snapshotShape(cliSnapshot))
	directCRL, err := direct.ShowCRL()
	require.NoError(t, err)
	cliCRL, err := cliPKI.ShowCRL()
	require.NoError(t, err)
	require.Len(t, cliCRL.RevokedCertificateEntries, len(directCRL.RevokedCertificateEntries))
	require.FileExists(t, filepath.Join(cliDir, "crl.pem"))
	require.FileExists(t, filepath.Join(cliDir, "crl.der"))
}

type comparableSnapshotShape struct {
	Statuses []storage.CertStatus
	Current  []string
	Expired  []string
	Renewed  []string
	Revoked  []string
}

func snapshotShape(snapshot *pki.Snapshot) comparableSnapshotShape {
	shape := comparableSnapshotShape{}
	for _, entry := range snapshot.Index {
		shape.Statuses = append(shape.Statuses, entry.Status)
	}
	for _, current := range snapshot.Current {
		shape.Current = append(shape.Current, current.Name)
	}
	for _, record := range snapshot.Lifecycle.Expired {
		shape.Expired = append(shape.Expired, record.Name)
	}
	for _, record := range snapshot.Lifecycle.Renewed {
		shape.Renewed = append(shape.Renewed, record.Name)
	}
	for _, record := range snapshot.Lifecycle.Revoked {
		shape.Revoked = append(shape.Revoked, record.Name)
	}
	sort.Slice(shape.Statuses, func(i, j int) bool { return shape.Statuses[i] < shape.Statuses[j] })
	sort.Strings(shape.Current)
	sort.Strings(shape.Expired)
	sort.Strings(shape.Renewed)
	sort.Strings(shape.Revoked)
	return shape
}
