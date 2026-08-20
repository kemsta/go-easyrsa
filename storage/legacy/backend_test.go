package legacy_test

import (
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
	"github.com/kemsta/go-easyrsa/v2/storage/legacy"
)

func TestBackendRejectsEntityDirectorySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional Windows privileges")
	}
	t.Parallel()

	pkiDir := t.TempDir()
	legitimate := filepath.Join(pkiDir, "legitimate")
	require.NoError(t, os.MkdirAll(legitimate, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(legitimate, "01.crt"), []byte("marker"), 0o644))
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "02.crt"), []byte("outside"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.pem"), []byte("secret"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(outside, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "issued", "client.crt"), []byte("renewed"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "evil")))
	require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "link")))
	require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "renewed")))
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret.pem"), filepath.Join(pkiDir, "crl.pem")))

	backend := legacy.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.View(func(components storage.Components) error {
		_, err := components.Keys().GetByName("evil")
		require.Error(t, err)
		_, err = components.Artifacts().GetArtifact("link/secret.pem")
		require.Error(t, err)
		_, err = components.Lifecycle().GetRenewedCertificate("client")
		require.Error(t, err)
		_, err = components.CRLs().Get()
		require.Error(t, err)
		return nil
	}))
}

func TestBackendRejectsEveryMutation(t *testing.T) {
	t.Parallel()

	backend := legacy.NewBackend(filepath.Join(t.TempDir(), "legacy"), "ca")
	require.True(t, backend.ReadOnly())
	require.ErrorIs(t, backend.EnsureLayout(), storage.ErrReadOnly)
	require.ErrorIs(t, backend.Initialize(false), storage.ErrReadOnly)
	require.ErrorIs(t, backend.Initialize(true), storage.ErrReadOnly)

	called := false
	err := backend.Update(func(storage.Components) error {
		called = true
		return nil
	})
	require.ErrorIs(t, err, storage.ErrReadOnly)
	require.False(t, called)

	require.NoError(t, backend.View(func(components storage.Components) error {
		require.ErrorIs(t, components.Keys().Put(&cert.Pair{Name: "client"}), storage.ErrReadOnly)
		require.ErrorIs(t, components.CSRs().PutCSR("client", []byte("request")), storage.ErrReadOnly)
		require.ErrorIs(t, components.Index().Record(storage.IndexEntry{}), storage.ErrReadOnly)
		_, err := components.Serials().Next()
		require.ErrorIs(t, err, storage.ErrReadOnly)
		require.ErrorIs(t, components.CRLs().Put([]byte("crl")), storage.ErrReadOnly)
		require.ErrorIs(t, components.Artifacts().PutArtifact(storage.Artifact{Path: "crl.pem"}), storage.ErrReadOnly)
		require.ErrorIs(t, components.Artifacts().DeleteArtifact("crl.pem"), storage.ErrReadOnly)
		require.ErrorIs(t, components.Lifecycle().MoveIssuedToRevoked("client", big.NewInt(1)), storage.ErrReadOnly)
		return nil
	}))
}
