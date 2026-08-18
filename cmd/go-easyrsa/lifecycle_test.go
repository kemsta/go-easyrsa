package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStagePKIMoves_RollbackRemovesCopiesAndKeepsSources(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))
	source := filepath.Join("issued", "alice.crt")
	destination := filepath.Join("revoked", "certs_by_serial", "01.crt")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, source), []byte("certificate"), 0o644))

	session, err := openLifecycleSession(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	staged, err := session.stageMoves([]lifecycleMove{{source: source, destination: destination}})
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(dir, source))
	require.FileExists(t, filepath.Join(dir, destination))

	require.NoError(t, staged.Rollback())
	require.FileExists(t, filepath.Join(dir, source))
	require.NoFileExists(t, filepath.Join(dir, destination))
}

func TestStagePKIMoves_RollbackReportsReplacement(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))
	source := filepath.Join("issued", "alice.crt")
	destination := filepath.Join("revoked", "certs_by_serial", "01.crt")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, source), []byte("certificate"), 0o644))

	session, err := openLifecycleSession(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	staged, err := session.stageMoves([]lifecycleMove{{source: source, destination: destination}})
	require.NoError(t, err)
	require.NoError(t, os.Rename(filepath.Join(dir, destination), filepath.Join(dir, "revoked", "certs_by_serial", "staged-original.crt")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, destination), []byte("replacement"), 0o644))

	err = staged.Rollback()
	require.Error(t, err)
	data, readErr := os.ReadFile(filepath.Join(dir, destination))
	require.NoError(t, readErr)
	require.Equal(t, []byte("replacement"), data)
}

func TestStagePKIMoves_RejectsSourceChangedAfterRead(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))
	source := filepath.Join("issued", "alice.crt")
	destination := filepath.Join("revoked", "certs_by_serial", "01.crt")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, source), []byte("original"), 0o644))

	session, err := openLifecycleSession(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	read, err := session.readRegular(source)
	require.NoError(t, err)
	require.NoError(t, os.Rename(filepath.Join(dir, source), filepath.Join(dir, "issued", "original.crt")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, source), []byte("replacement"), 0o644))

	_, err = session.stageMoves([]lifecycleMove{{
		source:         source,
		destination:    destination,
		expectedSource: read.info,
	}})
	require.Error(t, err)
	require.NoFileExists(t, filepath.Join(dir, destination))
}

func TestStagePKIMoves_CommitDoesNotDeleteReplacedSource(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))
	source := filepath.Join("issued", "alice.crt")
	destination := filepath.Join("revoked", "certs_by_serial", "01.crt")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, source), []byte("original"), 0o644))

	session, err := openLifecycleSession(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	staged, err := session.stageMoves([]lifecycleMove{{source: source, destination: destination}})
	require.NoError(t, err)
	require.NoError(t, os.Rename(filepath.Join(dir, source), filepath.Join(dir, "issued", "original.crt")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, source), []byte("replacement"), 0o644))

	err = staged.Commit()
	require.Error(t, err)
	data, readErr := os.ReadFile(filepath.Join(dir, source))
	require.NoError(t, readErr)
	require.Equal(t, []byte("replacement"), data)
}

func TestStagePKIMoves_CommitDoesNotDeleteSourceWhenDestinationChanges(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))
	source := filepath.Join("issued", "alice.crt")
	destination := filepath.Join("revoked", "certs_by_serial", "01.crt")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "issued"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, source), []byte("original"), 0o644))

	session, err := openLifecycleSession(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	staged, err := session.stageMoves([]lifecycleMove{{source: source, destination: destination}})
	require.NoError(t, err)
	require.NoError(t, os.Rename(filepath.Join(dir, destination), filepath.Join(dir, "revoked", "certs_by_serial", "staged-original.crt")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, destination), []byte("replacement"), 0o644))

	err = staged.Commit()
	require.Error(t, err)
	data, readErr := os.ReadFile(filepath.Join(dir, source))
	require.NoError(t, readErr)
	require.Equal(t, []byte("original"), data)
}

func TestPKIMutationLock_CanonicalizesSymlinkAliases(t *testing.T) {
	realPKI := t.TempDir()
	alias := filepath.Join(t.TempDir(), "pki-link")
	if err := os.Symlink(realPKI, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	first, err := acquirePKIMutationLock(realPKI)
	require.NoError(t, err)
	defer func() { require.NoError(t, first.Unlock()) }()
	_, err = acquirePKIMutationLock(alias)
	require.Error(t, err)
}

func TestLifecycleSession_ExcludesConcurrentMutation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.txt"), nil, 0o644))
	first, err := openLifecycleSession(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, first.Close()) }()

	_, err = openLifecycleSession(dir)
	require.Error(t, err)
}
