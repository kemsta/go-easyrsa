package fs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/kemsta/go-easyrsa/v2/storage"
)

const (
	transactionJournalVersion = 1
	journalStatePrepared      = "prepared"
	journalStateCommitted     = "committed"
)

type treeEntry struct {
	info  fs.FileInfo
	mode  fs.FileMode
	size  int64
	hash  [sha256.Size]byte
	isDir bool
}

type shadowTree struct {
	path         string
	originalInfo fs.FileInfo
	base         map[string]treeEntry
}

func newShadow(pkiDir string, copyExisting bool) (*shadowTree, error) {
	parent := filepath.Dir(pkiDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("storage/fs: create transaction parent: %w", err)
	}
	shadowPath, err := os.MkdirTemp(parent, "."+filepath.Base(pkiDir)+".txn-")
	if err != nil {
		return nil, fmt.Errorf("storage/fs: create transaction directory: %w", err)
	}
	shadow := &shadowTree{path: shadowPath, base: make(map[string]treeEntry)}
	fail := func(cause error) (*shadowTree, error) {
		return nil, errors.Join(cause, os.RemoveAll(shadowPath))
	}

	info, err := os.Lstat(pkiDir)
	if errors.Is(err, fs.ErrNotExist) {
		return shadow, nil
	}
	if err != nil {
		return fail(fmt.Errorf("storage/fs: inspect PKI root: %w", err))
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail(fmt.Errorf("storage/fs: PKI root is not a regular directory: %s", pkiDir))
	}
	shadow.originalInfo = info
	if err := os.Chmod(shadowPath, info.Mode().Perm()); err != nil {
		return fail(fmt.Errorf("storage/fs: set transaction directory mode: %w", err))
	}
	shadow.base, err = scanTree(pkiDir, shadowPath, copyExisting)
	if err != nil {
		return fail(err)
	}
	return shadow, nil
}

// scanTree records a regular-file/directory manifest. When copyExisting is
// true, regular files and directories are also copied beneath copyRoot.
func scanTree(root, copyRoot string, copyExisting bool) (map[string]treeEntry, error) {
	manifest := make(map[string]treeEntry)
	err := filepath.WalkDir(root, func(sourcePath string, directoryEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if sourcePath == root {
			return nil
		}
		relative, err := filepath.Rel(root, sourcePath)
		if err != nil {
			return err
		}
		if err := validateRelativeTreePath(relative); err != nil {
			return err
		}
		info, err := directoryEntry.Info()
		if err != nil {
			return fmt.Errorf("storage/fs: inspect %s: %w", relative, err)
		}
		entry := treeEntry{info: info, mode: info.Mode().Perm(), size: info.Size(), isDir: directoryEntry.IsDir()}
		switch {
		case directoryEntry.Type()&os.ModeSymlink != 0:
			return fmt.Errorf("storage/fs: transaction source is a symbolic link: %s", relative)
		case directoryEntry.IsDir():
			if copyExisting {
				if err := os.Mkdir(filepath.Join(copyRoot, relative), info.Mode().Perm()); err != nil {
					return fmt.Errorf("storage/fs: copy directory %s: %w", relative, err)
				}
			}
		case info.Mode().IsRegular():
			destination := ""
			if copyExisting {
				destination = filepath.Join(copyRoot, relative)
			}
			hash, err := copyAndHashRegularFile(sourcePath, destination, info)
			if err != nil {
				return fmt.Errorf("storage/fs: copy file %s: %w", relative, err)
			}
			entry.hash = hash
		default:
			return fmt.Errorf("storage/fs: transaction source is not regular: %s", relative)
		}
		manifest[relative] = entry
		return nil
	})
	return manifest, err
}

func validateRelativeTreePath(relative string) error {
	if relative == "" || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("storage/fs: path escaped PKI root: %s", relative)
	}
	return nil
}

func copyAndHashRegularFile(sourcePath, destinationPath string, expected fs.FileInfo) (sum [sha256.Size]byte, err error) {
	source, err := openRegularFile(sourcePath)
	if err != nil {
		return sum, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	openedInfo, err := source.Stat()
	if err != nil {
		return sum, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(expected, openedInfo) {
		return sum, fmt.Errorf("storage/fs: source changed while opening: %s", sourcePath)
	}

	hasher := sha256.New()
	writer := io.Writer(hasher)
	var destination *os.File
	if destinationPath != "" {
		if err := os.MkdirAll(filepath.Dir(destinationPath), 0o700); err != nil {
			return sum, err
		}
		destination, err = os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, expected.Mode().Perm())
		if err != nil {
			return sum, err
		}
		defer func() {
			if destination != nil {
				err = errors.Join(err, destination.Close())
			}
		}()
		writer = io.MultiWriter(hasher, destination)
	}
	if _, err := io.Copy(writer, source); err != nil {
		return sum, err
	}
	if destination != nil {
		if err := destination.Sync(); err != nil {
			return sum, err
		}
		if err := destination.Close(); err != nil {
			destination = nil
			return sum, err
		}
		destination = nil
	}
	copy(sum[:], hasher.Sum(nil))
	return sum, nil
}

func commitShadow(pkiDir string, shadow *shadowTree) error {
	if shadow == nil || shadow.path == "" {
		return errors.New("storage/fs: missing transaction directory")
	}
	if err := verifyUnchangedTree(pkiDir, shadow); err != nil {
		return err
	}
	desired, err := scanTree(shadow.path, "", false)
	if err != nil {
		return err
	}
	plan, err := buildCommitPlan(shadow.base, desired)
	if err != nil {
		return err
	}
	journal, err := newTransactionJournal(pkiDir, shadow.path)
	if err != nil {
		return err
	}
	fail := func(cause error) error {
		rollbackErr := journal.rollback()
		if rollbackErr == nil {
			_ = journal.cleanup()
		}
		return errors.Join(cause, rollbackErr)
	}

	if shadow.originalInfo == nil {
		rootInfo, err := os.Stat(shadow.path)
		if err != nil {
			return fail(err)
		}
		if err := journal.addDirectory(".", treeEntry{mode: rootInfo.Mode().Perm(), isDir: true}); err != nil {
			return fail(err)
		}
	}
	for _, relative := range plan.addDirectories {
		if err := journal.addDirectory(relative, desired[relative]); err != nil {
			return fail(err)
		}
	}
	for _, relative := range plan.chmodDirectories {
		if err := journal.chmodDirectory(relative, shadow.base[relative], desired[relative]); err != nil {
			return fail(err)
		}
	}
	for _, relative := range plan.writeFiles {
		var original *treeEntry
		if entry, ok := shadow.base[relative]; ok {
			original = &entry
		}
		if err := journal.writeFile(relative, original, filepath.Join(shadow.path, relative), desired[relative]); err != nil {
			return fail(err)
		}
	}
	for _, relative := range plan.deleteFiles {
		if err := journal.deleteFile(relative, shadow.base[relative]); err != nil {
			return fail(err)
		}
	}
	for _, relative := range plan.deleteDirectories {
		if err := journal.deleteDirectory(relative, shadow.base[relative]); err != nil {
			return fail(err)
		}
	}
	if err := journal.syncParents(); err != nil {
		return fail(err)
	}
	if err := journal.markCommitted(); err != nil {
		return fail(err)
	}
	// Once the committed marker is durable, cleanup failure must not make the
	// caller retry an already committed operation. A later backend mutation
	// removes any committed journal left behind.
	_ = journal.cleanup()
	return nil
}

func verifyUnchangedTree(pkiDir string, shadow *shadowTree) error {
	currentRoot, err := os.Lstat(pkiDir)
	switch {
	case shadow.originalInfo == nil && errors.Is(err, fs.ErrNotExist):
		return nil
	case shadow.originalInfo == nil:
		if err == nil {
			return fmt.Errorf("storage/fs: PKI root appeared during transaction: %w", storage.ErrConflict)
		}
		return err
	case err != nil:
		return fmt.Errorf("storage/fs: inspect PKI before commit: %w", err)
	case !os.SameFile(shadow.originalInfo, currentRoot):
		return fmt.Errorf("storage/fs: PKI root changed during transaction: %w", storage.ErrConflict)
	}

	current, err := scanTree(pkiDir, "", false)
	if err != nil {
		return err
	}
	if len(current) != len(shadow.base) {
		return fmt.Errorf("storage/fs: PKI contents changed during transaction: %w", storage.ErrConflict)
	}
	for relative, expected := range shadow.base {
		actual, ok := current[relative]
		if !ok || !sameTreeEntry(expected, actual) || !os.SameFile(expected.info, actual.info) {
			return fmt.Errorf("storage/fs: PKI path changed during transaction %s: %w", relative, storage.ErrConflict)
		}
	}
	return nil
}

type commitPlan struct {
	addDirectories    []string
	chmodDirectories  []string
	writeFiles        []string
	deleteFiles       []string
	deleteDirectories []string
}

func buildCommitPlan(base, desired map[string]treeEntry) (commitPlan, error) {
	var plan commitPlan
	for relative, wanted := range desired {
		original, exists := base[relative]
		if exists && original.isDir != wanted.isDir {
			return plan, fmt.Errorf("storage/fs: path type changed in transaction %s: %w", relative, storage.ErrConflict)
		}
		if wanted.isDir {
			switch {
			case !exists:
				plan.addDirectories = append(plan.addDirectories, relative)
			case original.mode != wanted.mode:
				plan.chmodDirectories = append(plan.chmodDirectories, relative)
			}
			continue
		}
		if !exists || !sameTreeEntry(original, wanted) {
			plan.writeFiles = append(plan.writeFiles, relative)
		}
	}
	for relative, original := range base {
		if _, exists := desired[relative]; exists {
			continue
		}
		if original.isDir {
			plan.deleteDirectories = append(plan.deleteDirectories, relative)
		} else {
			plan.deleteFiles = append(plan.deleteFiles, relative)
		}
	}
	sort.Slice(plan.addDirectories, func(i, j int) bool {
		leftDepth, rightDepth := pathDepth(plan.addDirectories[i]), pathDepth(plan.addDirectories[j])
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return plan.addDirectories[i] < plan.addDirectories[j]
	})
	sort.Strings(plan.chmodDirectories)
	sort.Strings(plan.writeFiles)
	sort.Strings(plan.deleteFiles)
	sort.Slice(plan.deleteDirectories, func(i, j int) bool {
		leftDepth, rightDepth := pathDepth(plan.deleteDirectories[i]), pathDepth(plan.deleteDirectories[j])
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return plan.deleteDirectories[i] > plan.deleteDirectories[j]
	})
	return plan, nil
}

func sameTreeEntry(left, right treeEntry) bool {
	if left.isDir != right.isDir || left.mode != right.mode {
		return false
	}
	if left.isDir {
		return true
	}
	return left.size == right.size && left.hash == right.hash
}

func pathDepth(name string) int {
	return strings.Count(filepath.Clean(name), string(filepath.Separator))
}

type journalEntry struct {
	Directory bool   `json:"directory"`
	Mode      uint32 `json:"mode"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

type journalAction struct {
	Relative string        `json:"relative"`
	Original *journalEntry `json:"original,omitempty"`
	Desired  *journalEntry `json:"desired,omitempty"`
	Backup   string        `json:"backup,omitempty"`
}

type journalManifest struct {
	Version int             `json:"version"`
	Root    string          `json:"root"`
	Work    string          `json:"work"`
	State   string          `json:"state"`
	Actions []journalAction `json:"actions"`
}

type transactionJournal struct {
	path     string
	manifest journalManifest
	parents  map[string]struct{}
}

func newTransactionJournal(root, work string) (*transactionJournal, error) {
	path := work + ".journal"
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	journal := &transactionJournal{
		path: path,
		manifest: journalManifest{
			Version: transactionJournalVersion,
			Root:    root,
			Work:    work,
			State:   journalStatePrepared,
		},
	}
	if err := journal.persist(); err != nil {
		return nil, errors.Join(err, os.RemoveAll(path))
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, errors.Join(err, os.RemoveAll(path))
	}
	return journal, nil
}

func (j *transactionJournal) persist() error {
	data, err := json.Marshal(j.manifest)
	if err != nil {
		return err
	}
	return writeAtomicMode(filepath.Join(j.path, "manifest.json"), data, 0o600)
}

func (j *transactionJournal) record(relative string, original, desired *treeEntry) error {
	if relative != "." {
		if err := validateRelativeTreePath(relative); err != nil {
			return err
		}
	}
	action := journalAction{Relative: relative, Original: journalEntryFromTree(original), Desired: journalEntryFromTree(desired)}
	if original != nil && !original.isDir {
		name := filepath.Join(j.manifest.Root, relative)
		if err := verifyCurrentEntry(name, *original); err != nil {
			return err
		}
		backupRelative := filepath.Join("backups", relative)
		backup := filepath.Join(j.path, backupRelative)
		if _, err := copyAndHashRegularFile(name, backup, original.info); err != nil {
			return err
		}
		action.Backup = backupRelative
		if err := syncDirectory(filepath.Dir(backup)); err != nil {
			return err
		}
	}
	j.manifest.Actions = append(j.manifest.Actions, action)
	return j.persist()
}

func journalEntryFromTree(entry *treeEntry) *journalEntry {
	if entry == nil {
		return nil
	}
	result := &journalEntry{Directory: entry.isDir, Mode: uint32(entry.mode.Perm()), Size: entry.size}
	if !entry.isDir {
		result.SHA256 = hex.EncodeToString(entry.hash[:])
	}
	return result
}

func (j *transactionJournal) addDirectory(relative string, desired treeEntry) error {
	name := filepath.Join(j.manifest.Root, relative)
	if _, err := os.Lstat(name); err == nil {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := j.record(relative, nil, &desired); err != nil {
		return err
	}
	if _, err := os.Lstat(name); err == nil {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(name, desired.mode); err != nil {
		return err
	}
	j.addParent(name)
	return nil
}

func (j *transactionJournal) chmodDirectory(relative string, original, desired treeEntry) error {
	name := filepath.Join(j.manifest.Root, relative)
	if err := verifyCurrentEntry(name, original); err != nil {
		return err
	}
	if err := j.record(relative, &original, &desired); err != nil {
		return err
	}
	if err := verifyCurrentEntry(name, original); err != nil {
		return err
	}
	if err := os.Chmod(name, desired.mode); err != nil {
		return err
	}
	j.addParent(name)
	return nil
}

func (j *transactionJournal) writeFile(relative string, original *treeEntry, source string, desired treeEntry) error {
	name := filepath.Join(j.manifest.Root, relative)
	if original != nil {
		if err := verifyCurrentEntry(name, *original); err != nil {
			return err
		}
	} else if _, err := os.Lstat(name); err == nil {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := j.record(relative, original, &desired); err != nil {
		return err
	}
	if original != nil {
		if err := verifyCurrentEntry(name, *original); err != nil {
			return err
		}
	} else if _, err := os.Lstat(name); err == nil {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if sha256.Sum256(data) != desired.hash {
		return fmt.Errorf("storage/fs: staged file changed before commit: %s", relative)
	}
	if err := writeAtomicMode(name, data, desired.mode); err != nil {
		return err
	}
	j.addParent(name)
	return nil
}

func (j *transactionJournal) deleteFile(relative string, original treeEntry) error {
	name := filepath.Join(j.manifest.Root, relative)
	if err := verifyCurrentEntry(name, original); err != nil {
		return err
	}
	if err := j.record(relative, &original, nil); err != nil {
		return err
	}
	if err := verifyCurrentEntry(name, original); err != nil {
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	j.addParent(name)
	return nil
}

func (j *transactionJournal) deleteDirectory(relative string, original treeEntry) error {
	name := filepath.Join(j.manifest.Root, relative)
	if err := verifyCurrentEntry(name, original); err != nil {
		return err
	}
	if err := j.record(relative, &original, nil); err != nil {
		return err
	}
	if err := verifyCurrentEntry(name, original); err != nil {
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	j.addParent(name)
	return nil
}

func (j *transactionJournal) markCommitted() error {
	j.manifest.State = journalStateCommitted
	return j.persist()
}

func (j *transactionJournal) rollback() error {
	var rollbackErrors []error
	for i := len(j.manifest.Actions) - 1; i >= 0; i-- {
		rollbackErrors = append(rollbackErrors, j.rollbackAction(j.manifest.Actions[i]))
	}
	rollbackErrors = append(rollbackErrors, j.syncParents())
	return errors.Join(rollbackErrors...)
}

func (j *transactionJournal) rollbackAction(action journalAction) error {
	name := filepath.Join(j.manifest.Root, action.Relative)
	current, exists, err := journalEntryAt(name)
	if err != nil {
		return err
	}
	matchesOriginal := exists && action.Original != nil && journalEntriesEqual(current, *action.Original)
	matchesDesired := exists && action.Desired != nil && journalEntriesEqual(current, *action.Desired)

	switch {
	case matchesOriginal:
		return nil // The recorded operation did not run, or was already restored.
	case action.Original == nil && !exists:
		return nil // An addition was never installed or is already removed.
	case action.Desired == nil && !exists:
		return j.restoreOriginal(name, action)
	case matchesDesired && action.Original == nil:
		if err := os.Remove(name); err != nil {
			return err
		}
		j.addParent(name)
		return nil
	case matchesDesired:
		return j.restoreOriginal(name, action)
	default:
		return fmt.Errorf("storage/fs: rollback path changed %s: %w", action.Relative, storage.ErrConflict)
	}
}

func (j *transactionJournal) restoreOriginal(name string, action journalAction) error {
	if action.Original == nil {
		return nil
	}
	mode := fs.FileMode(action.Original.Mode)
	if action.Original.Directory {
		if _, err := os.Lstat(name); errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(name, mode); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if err := os.Chmod(name, mode); err != nil {
			return err
		}
		j.addParent(name)
		return nil
	}
	backup := filepath.Join(j.path, action.Backup)
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	backupHash := sha256.Sum256(data)
	if int64(len(data)) != action.Original.Size || hex.EncodeToString(backupHash[:]) != action.Original.SHA256 {
		return fmt.Errorf("storage/fs: transaction backup is corrupt: %s", action.Relative)
	}
	if err := writeAtomicMode(name, data, mode); err != nil {
		return err
	}
	j.addParent(name)
	return nil
}

func journalEntryAt(name string) (journalEntry, bool, error) {
	info, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return journalEntry{}, false, nil
	}
	if err != nil {
		return journalEntry{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return journalEntry{}, false, fmt.Errorf("storage/fs: transaction path became a symbolic link: %s", name)
	}
	entry := journalEntry{Directory: info.IsDir(), Mode: uint32(info.Mode().Perm()), Size: info.Size()}
	if info.IsDir() {
		return entry, true, nil
	}
	if !info.Mode().IsRegular() {
		return journalEntry{}, false, fmt.Errorf("storage/fs: transaction path is not regular: %s", name)
	}
	hash, err := copyAndHashRegularFile(name, "", info)
	if err != nil {
		return journalEntry{}, false, err
	}
	entry.SHA256 = hex.EncodeToString(hash[:])
	return entry, true, nil
}

func journalEntriesEqual(left, right journalEntry) bool {
	if left.Directory != right.Directory || left.Mode != right.Mode {
		return false
	}
	if left.Directory {
		return true
	}
	return left.Size == right.Size && left.SHA256 == right.SHA256
}

func (j *transactionJournal) cleanup() error {
	journalErr := os.RemoveAll(j.path)
	parentErr := syncDirectory(filepath.Dir(j.path))
	return errors.Join(journalErr, parentErr)
}

func loadTransactionJournal(path string) (*transactionJournal, error) {
	data, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest journalManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	if manifest.Version != transactionJournalVersion || (manifest.State != journalStatePrepared && manifest.State != journalStateCommitted) {
		return nil, fmt.Errorf("storage/fs: invalid transaction journal %s", path)
	}
	return &transactionJournal{path: path, manifest: manifest}, nil
}

func recoverTransactions(pkiDir string) error {
	parent := filepath.Dir(pkiDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	prefix := "." + filepath.Base(pkiDir) + ".txn-"
	var journals []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".journal") {
			journals = append(journals, filepath.Join(parent, entry.Name()))
		}
	}
	sort.Strings(journals)
	for _, path := range journals {
		journal, err := loadTransactionJournal(path)
		if errors.Is(err, fs.ErrNotExist) {
			if removeErr := os.RemoveAll(path); removeErr != nil {
				return removeErr
			}
			continue
		}
		if err != nil {
			return err
		}
		if journal.manifest.Root != pkiDir || !safeTransactionSibling(parent, prefix, journal.manifest.Work) {
			return fmt.Errorf("storage/fs: transaction journal targets an unexpected path: %s", path)
		}
		if err := validateJournalActions(journal.manifest.Actions); err != nil {
			return fmt.Errorf("storage/fs: invalid transaction journal %s: %w", path, err)
		}
		if journal.manifest.State == journalStatePrepared {
			if err := journal.rollback(); err != nil {
				return fmt.Errorf("storage/fs: recover transaction %s: %w", path, err)
			}
		}
		if err := journal.cleanup(); err != nil {
			return err
		}
		if err := os.RemoveAll(journal.manifest.Work); err != nil {
			return err
		}
	}

	// A crash before the durable journal is created can leave only a work
	// directory. No live path has changed at that point, so it is safe to remove.
	entries, err = os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || strings.HasSuffix(entry.Name(), ".journal") {
			continue
		}
		work := filepath.Join(parent, entry.Name())
		if safeTransactionSibling(parent, prefix, work) {
			if err := os.RemoveAll(work); err != nil {
				return err
			}
		}
	}
	return syncDirectory(parent)
}

func hasPendingTransactions(pkiDir string) (bool, error) {
	parent := filepath.Dir(pkiDir)
	entries, err := os.ReadDir(parent)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	prefix := "." + filepath.Base(pkiDir) + ".txn-"
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".journal") {
			return true, nil
		}
	}
	return false, nil
}

func safeTransactionSibling(parent, prefix, name string) bool {
	clean := filepath.Clean(name)
	base := filepath.Base(clean)
	return filepath.Dir(clean) == parent && strings.HasPrefix(base, prefix) && !strings.HasSuffix(base, ".journal")
}

func validateJournalActions(actions []journalAction) error {
	for _, action := range actions {
		if action.Relative != "." {
			if err := validateRelativeTreePath(action.Relative); err != nil {
				return err
			}
		}
		if action.Backup == "" {
			continue
		}
		clean := filepath.Clean(action.Backup)
		if filepath.IsAbs(clean) || clean == "backups" || !strings.HasPrefix(clean, "backups"+string(filepath.Separator)) {
			return fmt.Errorf("backup path escaped journal: %s", action.Backup)
		}
	}
	return nil
}

func verifyCurrentEntry(name string, expected treeEntry) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !os.SameFile(expected.info, info) || info.IsDir() != expected.isDir || info.Mode().Perm() != expected.mode {
		return fmt.Errorf("storage/fs: path changed before commit %s: %w", name, storage.ErrConflict)
	}
	if expected.isDir {
		return nil
	}
	hash, err := copyAndHashRegularFile(name, "", info)
	if err != nil {
		return err
	}
	if hash != expected.hash || info.Size() != expected.size {
		return fmt.Errorf("storage/fs: file changed before commit %s: %w", name, storage.ErrConflict)
	}
	return nil
}

func (j *transactionJournal) addParent(name string) {
	if j.parents == nil {
		j.parents = make(map[string]struct{})
	}
	j.parents[filepath.Dir(name)] = struct{}{}
}

func (j *transactionJournal) syncParents() error {
	var syncErrors []error
	for parent := range j.parents {
		syncErrors = append(syncErrors, syncDirectory(parent))
	}
	return errors.Join(syncErrors...)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		if runtime.GOOS == "windows" || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
		return err
	}
	return nil
}
