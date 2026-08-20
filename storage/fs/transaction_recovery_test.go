package fs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestTransactionShadowRootRemainsPrivate(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o755))
	shadow, err := newShadow(pkiDir, true)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(shadow.path) })
	if runtime.GOOS != "windows" {
		info, err := os.Stat(shadow.path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

func TestRecoverTransactionsHandlesPreAppliedMarkerCrashWindows(t *testing.T) {
	t.Parallel()

	t.Run("write", func(t *testing.T) {
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
		index, err := journal.record("index.txt", &original, pointerToTreeEntry(desired["index.txt"]))
		require.NoError(t, err)
		staged, _, err := journal.stageFile(index, []byte("replacement"), 0o600)
		require.NoError(t, err)
		require.NoError(t, journal.root.Rename(staged, "index.txt"))
		closeJournalForCrash(t, journal)
		require.NoError(t, recoverTransactions(pkiDir))
		require.Equal(t, []byte("original"), readTestFile(t, indexPath))
	})

	t.Run("rollback restoration", func(t *testing.T) {
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
		_, _, err = journal.stageRestoration(0, []byte("original"), 0o600)
		require.NoError(t, err)
		closeJournalForCrash(t, journal)
		require.NoError(t, recoverTransactions(pkiDir))
		require.Equal(t, []byte("original"), readTestFile(t, indexPath))
	})

	t.Run("rollback restoration before identity persistence", func(t *testing.T) {
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
		restorePath := filepath.Join(journal.manifest.Internal, "staged", "restore-000000")
		restoring := *journal.manifest.Actions[0].Original
		restoring.Identity = nil
		journal.manifest.Actions[0].Restoring = &restoring
		journal.manifest.Actions[0].RestoreStage = restorePath
		require.NoError(t, journal.persist())
		require.NoError(t, journal.root.WriteFile(restorePath, []byte("partial"), 0o600))
		closeJournalForCrash(t, journal)
		require.NoError(t, recoverTransactions(pkiDir))
		require.Equal(t, []byte("original"), readTestFile(t, indexPath))
	})

	t.Run("delete", func(t *testing.T) {
		pkiDir := filepath.Join(t.TempDir(), "pki")
		require.NoError(t, os.MkdirAll(pkiDir, 0o755))
		indexPath := filepath.Join(pkiDir, "index.txt")
		require.NoError(t, os.WriteFile(indexPath, []byte("original"), 0o600))
		shadow, err := newShadow(pkiDir, true)
		require.NoError(t, err)
		journal, err := newTransactionJournal(pkiDir, shadow.path)
		require.NoError(t, err)
		original := shadow.base["index.txt"]
		index, err := journal.record("index.txt", &original, nil)
		require.NoError(t, err)
		moved, err := journal.prepareMove(index)
		require.NoError(t, err)
		require.NoError(t, journal.root.Rename("index.txt", moved))
		closeJournalForCrash(t, journal)
		require.NoError(t, recoverTransactions(pkiDir))
		require.Equal(t, []byte("original"), readTestFile(t, indexPath))
	})

	t.Run("directory", func(t *testing.T) {
		pkiDir := filepath.Join(t.TempDir(), "pki")
		require.NoError(t, os.MkdirAll(pkiDir, 0o755))
		shadow, err := newShadow(pkiDir, true)
		require.NoError(t, err)
		journal, err := newTransactionJournal(pkiDir, shadow.path)
		require.NoError(t, err)
		desired := treeEntry{mode: 0o755, isDir: true}
		index, err := journal.record("added", nil, &desired)
		require.NoError(t, err)
		staged, _, err := journal.stageDirectory(index, 0o755)
		require.NoError(t, err)
		require.NoError(t, journal.root.Rename(staged, "added"))
		closeJournalForCrash(t, journal)
		require.NoError(t, recoverTransactions(pkiDir))
		require.NoDirExists(t, filepath.Join(pkiDir, "added"))
	})
}

func pointerToTreeEntry(entry treeEntry) *treeEntry { return &entry }

func TestRecoverTransactionsCleansJournalCreatedBeforeMissingRootAction(t *testing.T) {
	t.Parallel()

	pkiDir := filepath.Join(t.TempDir(), "pki")
	shadow, err := newShadow(pkiDir, true)
	require.NoError(t, err)
	journal, err := newTransactionJournal(pkiDir, shadow.path)
	require.NoError(t, err)
	require.True(t, journal.manifest.RootInitiallyAbsent)
	require.Empty(t, journal.manifest.Actions)

	require.NoError(t, recoverTransactions(pkiDir))
	require.NoDirExists(t, pkiDir)
	require.NoDirExists(t, journal.path)
	require.NoDirExists(t, shadow.path)
}

func TestRecoverTransactionsRejectsReplacementPKIRoot(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	pkiDir := filepath.Join(parent, "pki")
	require.NoError(t, os.MkdirAll(pkiDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkiDir, "index.txt"), []byte("original"), 0o600))
	shadow, err := newShadow(pkiDir, true)
	require.NoError(t, err)
	journal, err := newTransactionJournal(pkiDir, shadow.path, shadow.originalInfo)
	require.NoError(t, err)
	require.NoError(t, journal.root.Close())
	journal.root = nil
	original := filepath.Join(parent, "original-pki")
	require.NoError(t, os.Rename(pkiDir, original))
	require.NoError(t, os.MkdirAll(pkiDir, 0o755))
	replacementMarker := filepath.Join(pkiDir, "replacement")
	require.NoError(t, os.WriteFile(replacementMarker, []byte("keep"), 0o600))

	err = recoverTransactions(pkiDir)
	require.ErrorIs(t, err, storage.ErrConflict)
	require.Equal(t, []byte("keep"), readTestFile(t, replacementMarker))
	require.DirExists(t, journal.path)
}

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
	closeJournalForCrash(t, journal)
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
	closeJournalForCrash(t, journal)

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

	closeJournalForCrash(t, journal)
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
	closeJournalForCrash(t, journal)
	require.NoError(t, os.WriteFile(indexPath, []byte("external"), 0o600))
	err = recoverTransactions(pkiDir)
	require.ErrorIs(t, err, storage.ErrConflict)
	require.Equal(t, []byte("external"), readTestFile(t, indexPath))
	require.DirExists(t, journal.path)
}

func closeJournalForCrash(t *testing.T, journal *transactionJournal) {
	t.Helper()
	if journal.root != nil {
		require.NoError(t, journal.root.Close())
		journal.root = nil
	}
}

func readTestFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	require.NoError(t, err)
	return data
}
