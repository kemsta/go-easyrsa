package fs_test

import (
	"bytes"
	"errors"
	iofs "io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/storage"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
	"github.com/kemsta/go-easyrsa/v2/storage/internal/testcontract"
)

func TestBackendWritableContract(t *testing.T) {
	t.Parallel()
	testcontract.RunWritableBackend(t, func(t *testing.T) storage.Backend {
		t.Helper()
		return fsstore.NewBackend(filepath.Join(t.TempDir(), "pki"), "ca")
	})
}

func TestBackendUpdateCommitsAndRollsBack(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())

	require.NoError(t, backend.Update(func(components storage.Components) error {
		require.NoError(t, components.CSRs().PutCSR("client", []byte("request")))
		return components.Artifacts().PutArtifact(storage.Artifact{
			Path:       "private/client.p12",
			Data:       []byte("archive"),
			Visibility: storage.ArtifactPrivate,
		})
	}))
	require.FileExists(t, filepath.Join(pkiDir, "reqs", "client.req"))
	require.FileExists(t, filepath.Join(pkiDir, "private", "client.p12"))

	callbackErr := errors.New("stop")
	err := backend.Update(func(components storage.Components) error {
		require.NoError(t, components.CSRs().PutCSR("rolled-back", []byte("request")))
		require.NoError(t, components.Artifacts().DeleteArtifact("private/client.p12"))
		return callbackErr
	})
	require.ErrorIs(t, err, callbackErr)
	require.NoFileExists(t, filepath.Join(pkiDir, "reqs", "rolled-back.req"))
	require.FileExists(t, filepath.Join(pkiDir, "private", "client.p12"))
}

func TestBackendViewDiscardsMutations(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	require.NoError(t, backend.View(func(components storage.Components) error {
		require.ErrorIs(t, components.CSRs().PutCSR("discarded", []byte("request")), storage.ErrReadOnly)
		return nil
	}))
	require.NoFileExists(t, filepath.Join(pkiDir, "reqs", "discarded.req"))
}

func TestBackendInitializeResetAndForeignProtection(t *testing.T) {
	t.Parallel()

	t.Run("owned", func(t *testing.T) {
		pkiDir := filepath.Join(t.TempDir(), "pki")
		backend := fsstore.NewBackend(pkiDir, "ca")
		require.NoError(t, backend.Initialize(false))
		require.NoError(t, os.WriteFile(filepath.Join(pkiDir, "index.txt"), []byte("index"), 0o600))
		require.ErrorIs(t, backend.Initialize(false), storage.ErrConflict)
		require.Equal(t, []byte("index"), mustReadFile(t, filepath.Join(pkiDir, "index.txt")))
		require.NoError(t, backend.Initialize(true))
		require.NoFileExists(t, filepath.Join(pkiDir, "index.txt"))
		require.DirExists(t, filepath.Join(pkiDir, "private"))
	})

	t.Run("foreign", func(t *testing.T) {
		pkiDir := filepath.Join(t.TempDir(), "pki")
		require.NoError(t, os.MkdirAll(pkiDir, 0o755))
		foreign := filepath.Join(pkiDir, "foreign.txt")
		require.NoError(t, os.WriteFile(foreign, []byte("keep"), 0o600))
		backend := fsstore.NewBackend(pkiDir, "ca")
		require.ErrorIs(t, backend.Initialize(true), storage.ErrForeignStorage)
		require.Equal(t, []byte("keep"), mustReadFile(t, foreign))
	})
}

func TestBackendArtifactsCopyAndModes(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	input := []byte("secret")
	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Artifacts().PutArtifact(storage.Artifact{
			Path:       "private/client.p12",
			Data:       input,
			Visibility: storage.ArtifactPrivate,
		})
	}))
	input[0] = 'X'

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(pkiDir, "private", "client.p12"))
		require.NoError(t, err)
		require.Equal(t, iofs.FileMode(0o600), info.Mode().Perm())
	}
	require.NoError(t, backend.View(func(components storage.Components) error {
		artifact, err := components.Artifacts().GetArtifact("private/client.p12")
		require.NoError(t, err)
		require.Equal(t, []byte("secret"), artifact.Data)
		artifact.Data[0] = 'Y'
		return nil
	}))
	require.Equal(t, []byte("secret"), mustReadFile(t, filepath.Join(pkiDir, "private", "client.p12")))
}

func TestBackendCrossProcessLock(t *testing.T) {
	if os.Getenv("GO_EASYRSA_FS_LOCK_HELPER") == "1" {
		pkiDir := os.Getenv("GO_EASYRSA_FS_LOCK_PKI")
		ready := os.Getenv("GO_EASYRSA_FS_LOCK_READY")
		release := os.Getenv("GO_EASYRSA_FS_LOCK_RELEASE")
		backend := fsstore.NewBackend(pkiDir, "ca")
		require.NoError(t, backend.Update(func(storage.Components) error {
			require.NoError(t, os.WriteFile(ready, []byte("ready"), 0o600))
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(release); err == nil {
					return nil
				}
				time.Sleep(10 * time.Millisecond)
			}
			return errors.New("timed out waiting for parent")
		}))
		return
	}

	parent := t.TempDir()
	pkiDir := filepath.Join(parent, "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	ready := filepath.Join(parent, "ready")
	release := filepath.Join(parent, "release")
	command := exec.Command(os.Args[0], "-test.run=^TestBackendCrossProcessLock$")
	command.Env = append(os.Environ(),
		"GO_EASYRSA_FS_LOCK_HELPER=1",
		"GO_EASYRSA_FS_LOCK_PKI="+pkiDir,
		"GO_EASYRSA_FS_LOCK_READY="+ready,
		"GO_EASYRSA_FS_LOCK_RELEASE="+release,
	)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = os.WriteFile(release, []byte("release"), 0o600)
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	require.Eventually(t, func() bool {
		_, err := os.Stat(ready)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "helper process did not acquire the lock")

	err := backend.Update(func(storage.Components) error { return nil })
	require.ErrorIs(t, err, storage.ErrConflict)
	err = backend.View(func(storage.Components) error { return nil })
	require.ErrorIs(t, err, storage.ErrConflict)
	require.NoError(t, os.WriteFile(release, []byte("release"), 0o600))
	require.NoError(t, command.Wait(), output.String())
}

func TestBackendExcludesConcurrentInstances(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	first := fsstore.NewBackend(pkiDir, "ca")
	second := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, first.EnsureLayout())
	entered := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- first.Update(func(storage.Components) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	err := second.Update(func(storage.Components) error { return nil })
	require.ErrorIs(t, err, storage.ErrConflict)
	close(release)
	require.NoError(t, <-firstResult)
}

func TestBackendRejectsPathEscape(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	pkiDir := filepath.Join(parent, "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	victim := filepath.Join(parent, "victim.req")
	err := backend.Update(func(components storage.Components) error {
		return components.CSRs().PutCSR("../../victim", []byte("escape"))
	})
	require.Error(t, err)
	require.NoFileExists(t, victim)
}

func TestBackendUpdateRejectsSymlinkedPKIFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional Windows privileges")
	}
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	outside := filepath.Join(t.TempDir(), "outside.crt")
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(pkiDir, "issued", "client.crt")))
	called := false
	err := backend.Update(func(storage.Components) error {
		called = true
		return nil
	})
	require.Error(t, err)
	require.False(t, called)
	require.Equal(t, []byte("outside"), mustReadFile(t, outside))
}

func TestBackendDetectsUncoordinatedLiveChange(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	marker := filepath.Join(pkiDir, "marker.txt")
	require.NoError(t, os.WriteFile(marker, []byte("before"), 0o600))

	err := backend.Update(func(components storage.Components) error {
		require.NoError(t, components.CSRs().PutCSR("client", []byte("request")))
		return os.WriteFile(marker, []byte("external"), 0o600)
	})
	require.ErrorIs(t, err, storage.ErrConflict)
	require.Equal(t, []byte("external"), mustReadFile(t, marker))
	require.NoFileExists(t, filepath.Join(pkiDir, "reqs", "client.req"))
}

func TestBackendViewCreatesOnlySiblingLock(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	pkiDir := filepath.Join(parent, "pki")
	require.NoError(t, fsstore.InitDirs(pkiDir))
	backend := fsstore.NewBackend(pkiDir, "ca")
	lockPath := filepath.Join(parent, ".pki.go-easyrsa.lock")
	require.NoFileExists(t, lockPath)
	before, err := os.ReadDir(pkiDir)
	require.NoError(t, err)
	require.NoError(t, backend.View(func(components storage.Components) error {
		_, err := components.CSRs().GetCSR("missing")
		require.ErrorIs(t, err, storage.ErrNotFound)
		return nil
	}))
	require.FileExists(t, lockPath)
	after, err := os.ReadDir(pkiDir)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestBackendLifecycleMoves(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	backend := fsstore.NewBackend(pkiDir, "ca")
	require.NoError(t, backend.EnsureLayout())
	require.NoError(t, os.WriteFile(filepath.Join(pkiDir, "issued", "client.crt"), []byte("certificate"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pkiDir, "private", "client.key"), []byte("key"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pkiDir, "reqs", "client.req"), []byte("request"), 0o644))

	require.NoError(t, backend.Update(func(components storage.Components) error {
		return components.Lifecycle().MoveIssuedToRevoked("client", big.NewInt(10))
	}))
	require.NoFileExists(t, filepath.Join(pkiDir, "issued", "client.crt"))
	require.NoFileExists(t, filepath.Join(pkiDir, "private", "client.key"))
	require.NoFileExists(t, filepath.Join(pkiDir, "reqs", "client.req"))
	require.Equal(t, []byte("certificate"), mustReadFile(t, filepath.Join(pkiDir, "revoked", "certs_by_serial", "0A.crt")))
	require.Equal(t, []byte("key"), mustReadFile(t, filepath.Join(pkiDir, "revoked", "private_by_serial", "0A.key")))
	require.Equal(t, []byte("request"), mustReadFile(t, filepath.Join(pkiDir, "revoked", "reqs_by_serial", "0A.req")))
}

func mustReadFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	return data
}
