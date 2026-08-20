package fs_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestLifecycleListRenewedIncludesNamedAndSerialArchives(t *testing.T) {
	t.Parallel()
	pkiDir, backend, namedPEM, namedSerial, historicalPEM, historicalSerial := renewalArchiveFixture(t)

	require.NoError(t, backend.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Len(t, archives, 2)
		require.Equal(t, "named", archives[0].Name)
		require.Equal(t, storage.RenewalArchiveIssued, archives[0].Source)
		require.Zero(t, archives[0].Serial.Cmp(namedSerial))
		require.Equal(t, namedPEM, archives[0].CertificatePEM)
		require.Empty(t, archives[1].Name)
		require.Equal(t, storage.RenewalArchiveBySerial, archives[1].Source)
		require.Zero(t, archives[1].Serial.Cmp(historicalSerial))
		require.Equal(t, historicalPEM, archives[1].CertificatePEM)
		archives[0].Serial.SetInt64(999)
		archives[0].CertificatePEM[0] ^= 0xff
		return nil
	}))

	require.NoError(t, backend.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Len(t, archives, 2)
		require.Zero(t, archives[0].Serial.Cmp(namedSerial))
		require.Equal(t, namedPEM, archives[0].CertificatePEM)
		return nil
	}))
	require.FileExists(t, filepath.Join(pkiDir, "renewed", "certs_by_serial", storage.HexSerial(historicalSerial)+".crt"))
}

func TestLifecycleListRenewedRejectsDuplicateSerialAcrossSources(t *testing.T) {
	t.Parallel()
	pkiDir, backend, namedPEM, namedSerial, _, _ := renewalArchiveFixture(t)
	historicalDir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
	require.NoError(t, os.WriteFile(filepath.Join(historicalDir, storage.HexSerial(namedSerial)+".crt"), namedPEM, 0o644))

	err := backend.View(func(components storage.Components) error {
		_, err := components.Lifecycle().ListRenewed()
		return err
	})
	require.ErrorIs(t, err, storage.ErrConflict)
}

func TestLifecycleListRenewedRejectsInvalidCandidates(t *testing.T) {
	t.Parallel()
	_, _, validPEM, validSerial, _, otherSerial := renewalArchiveFixture(t)

	tests := []struct {
		name  string
		setup func(t *testing.T, pkiDir string)
	}{
		{name: "malformed certificate", setup: func(t *testing.T, pkiDir string) {
			dir := filepath.Join(pkiDir, "renewed", "issued")
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "broken.crt"), []byte("broken"), 0o644))
		}},
		{name: "directory", setup: func(t *testing.T, pkiDir string) {
			require.NoError(t, os.MkdirAll(filepath.Join(pkiDir, "renewed", "issued", "client.crt"), 0o755))
		}},
		{name: "symlink", setup: func(t *testing.T, pkiDir string) {
			target := filepath.Join(t.TempDir(), "outside.crt")
			require.NoError(t, os.WriteFile(target, validPEM, 0o644))
			dir := filepath.Join(pkiDir, "renewed", "issued")
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NoError(t, os.Symlink(target, filepath.Join(dir, "client.crt")))
		}},
		{name: "archive directory symlink", setup: func(t *testing.T, pkiDir string) {
			outside := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(outside, "client.crt"), validPEM, 0o644))
			require.NoError(t, os.MkdirAll(filepath.Join(pkiDir, "renewed"), 0o755))
			require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "renewed", "issued")))
		}},
		{name: "renewed parent symlink", setup: func(t *testing.T, pkiDir string) {
			outside := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(outside, "issued"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(outside, "issued", "client.crt"), validPEM, 0o644))
			require.NoError(t, os.RemoveAll(filepath.Join(pkiDir, "renewed")))
			require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "renewed")))
		}},
		{name: "invalid serial filename", setup: func(t *testing.T, pkiDir string) {
			dir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "not-hex.crt"), validPEM, 0o644))
		}},
		{name: "serial mismatch", setup: func(t *testing.T, pkiDir string) {
			dir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NotZero(t, validSerial.Cmp(otherSerial))
			require.NoError(t, os.WriteFile(filepath.Join(dir, storage.HexSerial(otherSerial)+".crt"), validPEM, 0o644))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkiDir := filepath.Join(t.TempDir(), "pki")
			require.NoError(t, os.MkdirAll(pkiDir, 0o755))
			backend := fsstore.NewBackend(pkiDir, "ca")
			require.NoError(t, backend.EnsureLayout())
			tt.setup(t, pkiDir)
			err := backend.View(func(components storage.Components) error {
				_, err := components.Lifecycle().ListRenewed()
				return err
			})
			require.Error(t, err)
		})
	}
}

func TestFilesystemLifecycleStatePreservesRenewalSources(t *testing.T) {
	t.Parallel()
	_, source, _, namedSerial, _, historicalSerial := renewalArchiveFixture(t)
	var state storage.LifecycleState
	require.NoError(t, source.View(func(components storage.Components) error {
		var err error
		state, err = components.Lifecycle().ExportState()
		return err
	}))
	require.Len(t, state.Renewed, 2)
	require.Equal(t, storage.RenewalArchiveIssued, state.Renewed[0].RenewalSource)
	require.Equal(t, storage.RenewalArchiveBySerial, state.Renewed[1].RenewalSource)

	targetDir := filepath.Join(t.TempDir(), "pki")
	target := fsstore.NewBackend(targetDir, "ca")
	require.NoError(t, target.EnsureLayout())
	historicalSidecar := filepath.Join(targetDir, "certs_by_serial", storage.HexSerial(historicalSerial)+".name")
	require.NoError(t, os.WriteFile(historicalSidecar, []byte("original-storage-name"), 0o600))
	require.NoError(t, target.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(state)
	}))
	require.FileExists(t, filepath.Join(targetDir, "renewed", "issued", "named.crt"))
	require.FileExists(t, filepath.Join(targetDir, "renewed", "certs_by_serial", storage.HexSerial(historicalSerial)+".crt"))
	require.NoFileExists(t, filepath.Join(targetDir, "renewed", "issued", state.Renewed[1].Name+".crt"))
	sidecarData, err := os.ReadFile(historicalSidecar)
	require.NoError(t, err)
	require.Equal(t, []byte("original-storage-name"), sidecarData)
	require.NoError(t, target.View(func(components storage.Components) error {
		archives, err := components.Lifecycle().ListRenewed()
		require.NoError(t, err)
		require.Len(t, archives, 2)
		require.Zero(t, archives[0].Serial.Cmp(namedSerial))
		require.Zero(t, archives[1].Serial.Cmp(historicalSerial))
		return nil
	}))
}

func TestFilesystemLifecycleStateHonorsCaseInsensitivePathCollisions(t *testing.T) {
	t.Parallel()
	source, err := pki.NewWithMemory(pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = source.BuildCA()
	require.NoError(t, err)
	for _, name := range []string{"alice", "ALICE"} {
		_, err = source.BuildClientFull(name)
		require.NoError(t, err)
		_, err = source.Renew(name)
		require.NoError(t, err)
	}
	snapshot, err := source.ExportSnapshot()
	require.NoError(t, err)
	require.Len(t, snapshot.Lifecycle.Renewed, 2)

	targetDir := filepath.Join(t.TempDir(), "pki")
	target := fsstore.NewBackend(targetDir, "ca")
	require.NoError(t, target.EnsureLayout())
	err = target.Update(func(components storage.Components) error {
		return components.Lifecycle().ReplaceState(snapshot.Lifecycle)
	})
	if filesystemCaseInsensitive(t, targetDir) {
		require.ErrorIs(t, err, storage.ErrConflict)
		return
	}
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(targetDir, "renewed", "issued", "alice.crt"))
	require.FileExists(t, filepath.Join(targetDir, "renewed", "issued", "ALICE.crt"))
}

func TestFilesystemLifecycleStateRejectsInvalidRenewalSources(t *testing.T) {
	t.Parallel()
	_, backend, namedPEM, namedSerial, _, _ := renewalArchiveFixture(t)

	tests := []storage.LifecycleRecord{
		{Name: "client", Serial: new(big.Int).Set(namedSerial), CertificatePEM: namedPEM, RenewalSource: "unknown"},
		{Name: "client", Serial: new(big.Int).Set(namedSerial), CertificatePEM: namedPEM, RenewalSource: storage.RenewalArchiveBySerial, PrivateKeyPEM: []byte("key")},
		{Name: "different-name", Serial: new(big.Int).Set(namedSerial), CertificatePEM: namedPEM, RenewalSource: storage.RenewalArchiveBySerial},
	}
	for _, record := range tests {
		err := backend.Update(func(components storage.Components) error {
			return components.Lifecycle().ReplaceState(storage.LifecycleState{Renewed: []storage.LifecycleRecord{record}})
		})
		require.Error(t, err)
	}
}

func filesystemCaseInsensitive(t *testing.T, directory string) bool {
	t.Helper()
	probe := filepath.Join(directory, "case-probe")
	require.NoError(t, os.WriteFile(probe, []byte("probe"), 0o600))
	_, err := os.Stat(filepath.Join(directory, "CASE-PROBE"))
	require.NoError(t, os.Remove(probe))
	return err == nil
}

func renewalArchiveFixture(t *testing.T) (string, storage.Backend, []byte, *big.Int, []byte, *big.Int) {
	t.Helper()
	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk, err := pki.NewWithFS(pkiDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	_, err = pk.BuildCA()
	require.NoError(t, err)
	named, err := pk.BuildClientFull("named")
	require.NoError(t, err)
	namedSerial, err := named.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("named")
	require.NoError(t, err)
	historical, err := pk.BuildClientFull("historical")
	require.NoError(t, err)
	historicalSerial, err := historical.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("historical")
	require.NoError(t, err)

	historicalDir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
	require.NoError(t, os.MkdirAll(historicalDir, 0o755))
	require.NoError(t, os.Rename(
		filepath.Join(pkiDir, "renewed", "issued", "historical.crt"),
		filepath.Join(historicalDir, storage.HexSerial(historicalSerial)+".crt"),
	))
	require.NoError(t, os.WriteFile(filepath.Join(pkiDir, "renewed", "issued", "README.txt"), []byte("ignored"), 0o644))
	backend := fsstore.NewBackend(pkiDir, "ca")
	return pkiDir, backend, append([]byte(nil), named.CertPEM...), new(big.Int).Set(namedSerial), append([]byte(nil), historical.CertPEM...), new(big.Int).Set(historicalSerial)
}
