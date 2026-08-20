package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestRecoverTransactionsRollsBackPreparedJournal(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o755))
	indexPath := filepath.Join(pkiDir, "index.txt")
	require.NoError(t, os.WriteFile(indexPath, []byte("original"), 0o600))
	shadow, err := newShadow(pkiDir, true)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(shadow.path, "index.txt"), []byte("replacement"), 0o600))
	desired, err := scanTree(shadow.path, "", false)
	require.NoError(t, err)
	journal, err := newTransactionJournal(pkiDir, shadow.path)
	require.NoError(t, err)
	original := shadow.base["index.txt"]
	require.NoError(t, journal.writeFile("index.txt", &original, filepath.Join(shadow.path, "index.txt"), desired["index.txt"]))
	require.Equal(t, []byte("replacement"), readTestFile(t, indexPath))

	// Simulate process death: do not call rollback, markCommitted, or cleanup.
	require.NoError(t, recoverTransactions(pkiDir))
	require.Equal(t, []byte("original"), readTestFile(t, indexPath))
	require.NoDirExists(t, shadow.path)
	require.NoDirExists(t, journal.path)
}

func TestRecoverTransactionsKeepsDurablyCommittedState(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o755))
	indexPath := filepath.Join(pkiDir, "index.txt")
	require.NoError(t, os.WriteFile(indexPath, []byte("original"), 0o600))
	shadow, err := newShadow(pkiDir, true)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(shadow.path, "index.txt"), []byte("committed"), 0o600))
	desired, err := scanTree(shadow.path, "", false)
	require.NoError(t, err)
	journal, err := newTransactionJournal(pkiDir, shadow.path)
	require.NoError(t, err)
	original := shadow.base["index.txt"]
	require.NoError(t, journal.writeFile("index.txt", &original, filepath.Join(shadow.path, "index.txt"), desired["index.txt"]))
	require.NoError(t, journal.syncParents())
	require.NoError(t, journal.markCommitted())

	require.NoError(t, recoverTransactions(pkiDir))
	require.Equal(t, []byte("committed"), readTestFile(t, indexPath))
	require.NoDirExists(t, shadow.path)
	require.NoDirExists(t, journal.path)
}

func TestRecoverTransactionsPreservesByteIdenticalReplacement(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o755))
	indexPath := filepath.Join(pkiDir, "index.txt")
	require.NoError(t, os.WriteFile(indexPath, []byte("original"), 0o600))
	shadow, err := newShadow(pkiDir, true)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(shadow.path, "index.txt"), []byte("transaction"), 0o600))
	desired, err := scanTree(shadow.path, "", false)
	require.NoError(t, err)
	journal, err := newTransactionJournal(pkiDir, shadow.path)
	require.NoError(t, err)
	original := shadow.base["index.txt"]
	require.NoError(t, journal.writeFile("index.txt", &original, filepath.Join(shadow.path, "index.txt"), desired["index.txt"]))

	replacement := filepath.Join(pkiDir, "replacement")
	require.NoError(t, os.WriteFile(replacement, []byte("transaction"), 0o600))
	require.NoError(t, os.Remove(indexPath))
	require.NoError(t, os.Rename(replacement, indexPath))
	err = recoverTransactions(pkiDir)
	require.ErrorIs(t, err, storage.ErrConflict)
	require.Equal(t, []byte("transaction"), readTestFile(t, indexPath))
	require.DirExists(t, journal.path)
}

func TestRecoverTransactionsPreservesExternalReplacement(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o755))
	indexPath := filepath.Join(pkiDir, "index.txt")
	require.NoError(t, os.WriteFile(indexPath, []byte("original"), 0o600))
	shadow, err := newShadow(pkiDir, true)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(shadow.path, "index.txt"), []byte("transaction"), 0o600))
	desired, err := scanTree(shadow.path, "", false)
	require.NoError(t, err)
	journal, err := newTransactionJournal(pkiDir, shadow.path)
	require.NoError(t, err)
	original := shadow.base["index.txt"]
	require.NoError(t, journal.writeFile("index.txt", &original, filepath.Join(shadow.path, "index.txt"), desired["index.txt"]))

	// An uncoordinated writer changes the installed inode in place. Recovery
	// must detect the content mismatch rather than overwrite it from backup.
	require.NoError(t, os.WriteFile(indexPath, []byte("external"), 0o600))
	err = recoverTransactions(pkiDir)
	require.ErrorIs(t, err, storage.ErrConflict)
	require.Equal(t, []byte("external"), readTestFile(t, indexPath))
	require.DirExists(t, journal.path)
}

func readTestFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	return data
}
