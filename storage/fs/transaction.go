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
	"reflect"
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
	// Keep the transaction snapshot private even when the live PKI root is
	// world-readable; individual copied file modes are preserved below.
	shadow.base, err = scanTreeWithRoot(pkiDir, shadowPath, copyExisting, info)
	if err != nil {
		return fail(err)
	}
	return shadow, nil
}

// scanTree records a confined regular-file/directory manifest. When
// copyExisting is true, files and directories are copied beneath copyRoot.
func scanTree(rootPath, copyRoot string, copyExisting bool) (map[string]treeEntry, error) {
	return scanTreeWithRoot(rootPath, copyRoot, copyExisting, nil)
}

func scanTreeWithRoot(rootPath, copyRoot string, copyExisting bool, expectedRoot fs.FileInfo) (manifest map[string]treeEntry, err error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	var destinationRoot *os.Root
	if copyExisting {
		destinationRoot, err = os.OpenRoot(copyRoot)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, destinationRoot.Close()) }()
	}
	if expectedRoot != nil {
		openedRoot, err := root.Stat(".")
		if err != nil {
			return nil, err
		}
		if !openedRoot.IsDir() || !os.SameFile(expectedRoot, openedRoot) {
			return nil, fmt.Errorf("storage/fs: PKI root identity changed: %w", storage.ErrConflict)
		}
	}
	manifest = make(map[string]treeEntry)
	err = fs.WalkDir(root.FS(), ".", func(fsName string, directoryEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fsName == "." {
			return nil
		}
		relative := filepath.FromSlash(fsName)
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
				if err := destinationRoot.Mkdir(relative, info.Mode().Perm()); err != nil {
					return fmt.Errorf("storage/fs: copy directory %s: %w", relative, err)
				}
			}
		case info.Mode().IsRegular():
			hash, err := copyAndHashRootFile(root, fsName, destinationRoot, relative, info)
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

func copyAndHashRootFile(root *os.Root, sourceName string, destinationRoot *os.Root, destinationName string, expected fs.FileInfo) (sum [sha256.Size]byte, err error) {
	source, err := openRootRegular(root, sourceName)
	if err != nil {
		return sum, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	openedInfo, err := source.Stat()
	if err != nil {
		return sum, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(expected, openedInfo) {
		return sum, fmt.Errorf("storage/fs: source changed while opening: %s", sourceName)
	}

	hasher := sha256.New()
	writer := io.Writer(hasher)
	var destination *os.File
	if destinationRoot != nil {
		destination, err = destinationRoot.OpenFile(destinationName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, expected.Mode().Perm())
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
	journal, err := newTransactionJournal(pkiDir, shadow.path, shadow.originalInfo)
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

	current, err := scanTreeWithRoot(pkiDir, "", false, shadow.originalInfo)
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

type journalIdentity struct {
	Device uint64 `json:"device"`
	File   uint64 `json:"file"`
}

type journalEntry struct {
	Directory bool             `json:"directory"`
	Mode      uint32           `json:"mode"`
	Size      int64            `json:"size,omitempty"`
	SHA256    string           `json:"sha256,omitempty"`
	Identity  *journalIdentity `json:"identity,omitempty"`
}

type journalAction struct {
	Relative     string        `json:"relative"`
	Original     *journalEntry `json:"original,omitempty"`
	Desired      *journalEntry `json:"desired,omitempty"`
	Backup       string        `json:"backup,omitempty"`
	Staged       string        `json:"staged,omitempty"`
	Moved        string        `json:"moved,omitempty"`
	Restoring    *journalEntry `json:"restoring,omitempty"`
	RestoreStage string        `json:"restore_stage,omitempty"`
	Applied      bool          `json:"applied,omitempty"`
}

type journalManifest struct {
	Version             int              `json:"version"`
	Root                string           `json:"root"`
	Work                string           `json:"work"`
	Internal            string           `json:"internal"`
	RootIdentity        *journalIdentity `json:"root_identity,omitempty"`
	RootInitiallyAbsent bool             `json:"root_initially_absent,omitempty"`
	State               string           `json:"state"`
	Actions             []journalAction  `json:"actions"`
}

type transactionJournal struct {
	path      string
	manifest  journalManifest
	parents   map[string]struct{}
	installed map[int]fs.FileInfo
	moved     map[int]fs.FileInfo
	root      *os.Root
}

func newTransactionJournal(root, work string, expectedRoot ...fs.FileInfo) (*transactionJournal, error) {
	path := work + ".journal"
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	journal := &transactionJournal{
		path: path,
		manifest: journalManifest{
			Version:  transactionJournalVersion,
			Root:     root,
			Work:     work,
			Internal: ".go-easyrsa-txn-" + strings.TrimPrefix(filepath.Base(work), "."+filepath.Base(root)+".txn-"),
			State:    journalStatePrepared,
		},
	}
	if rootHandle, openErr := os.OpenRoot(root); openErr == nil {
		openedInfo, statErr := rootHandle.Stat(".")
		if statErr != nil || (len(expectedRoot) > 0 && expectedRoot[0] != nil && !os.SameFile(expectedRoot[0], openedInfo)) {
			_ = rootHandle.Close()
			return nil, errors.Join(statErr, os.RemoveAll(path), fmt.Errorf("storage/fs: PKI root changed before transaction journal: %w", storage.ErrConflict))
		}
		journal.manifest.RootIdentity = journalIdentityFromInfo(openedInfo)
		journal.root = rootHandle
	} else if errors.Is(openErr, fs.ErrNotExist) {
		journal.manifest.RootInitiallyAbsent = true
	} else {
		return nil, errors.Join(openErr, os.RemoveAll(path))
	}
	if err := journal.persist(); err != nil {
		if journal.root != nil {
			_ = journal.root.Close()
		}
		return nil, errors.Join(err, os.RemoveAll(path))
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		if journal.root != nil {
			_ = journal.root.Close()
		}
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

func (j *transactionJournal) record(relative string, original, desired *treeEntry) (int, error) {
	if relative != "." {
		if err := validateRelativeTreePath(relative); err != nil {
			return 0, err
		}
	}
	action := journalAction{Relative: relative, Original: journalEntryFromTree(original, true), Desired: journalEntryFromTree(desired, false)}
	if original != nil && !original.isDir {
		if err := j.verifyEntry(relative, *original); err != nil {
			return 0, err
		}
		backupRelative := filepath.Join("backups", relative)
		backup := filepath.Join(j.path, backupRelative)
		if err := j.backupRootFile(relative, backup, original.info); err != nil {
			return 0, err
		}
		action.Backup = backupRelative
		if err := syncDirectory(filepath.Dir(backup)); err != nil {
			return 0, err
		}
	}
	j.manifest.Actions = append(j.manifest.Actions, action)
	index := len(j.manifest.Actions) - 1
	return index, j.persist()
}

func journalEntryFromTree(entry *treeEntry, includeIdentity bool) *journalEntry {
	if entry == nil {
		return nil
	}
	result := &journalEntry{Directory: entry.isDir, Mode: uint32(entry.mode.Perm()), Size: entry.size}
	if includeIdentity {
		result.Identity = journalIdentityFromInfo(entry.info)
	}
	if !entry.isDir {
		result.SHA256 = hex.EncodeToString(entry.hash[:])
	}
	return result
}

func journalIdentityFromInfo(info fs.FileInfo) *journalIdentity {
	if info == nil || info.Sys() == nil {
		return nil
	}
	// SameFile forces lazy platform file IDs to be loaded on Windows.
	_ = os.SameFile(info, info)
	value := reflect.ValueOf(info.Sys())
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil
	}
	device, deviceOK := reflectedUint(value.FieldByName("Dev"))
	file, fileOK := reflectedUint(value.FieldByName("Ino"))
	if deviceOK && fileOK {
		return &journalIdentity{Device: device, File: file}
	}
	if identity := reflectedWindowsIdentity(value); identity != nil {
		return identity
	}
	// os.FileInfo.Sys intentionally hides Windows file IDs. The concrete
	// *os.fileStat retains the lazily loaded volume/index fields used by
	// os.SameFile, which reflection can read without converting them to an
	// interface.
	concrete := reflect.ValueOf(info)
	for concrete.Kind() == reflect.Pointer || concrete.Kind() == reflect.Interface {
		if concrete.IsNil() {
			return nil
		}
		concrete = concrete.Elem()
	}
	return reflectedWindowsIdentity(concrete)
}

func reflectedWindowsIdentity(value reflect.Value) *journalIdentity {
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return nil
	}
	volume, volumeOK := reflectedUint(value.FieldByName("vol"))
	indexHigh, highOK := reflectedUint(value.FieldByName("idxhi"))
	indexLow, lowOK := reflectedUint(value.FieldByName("idxlo"))
	if !volumeOK || !highOK || !lowOK || (indexHigh == 0 && indexLow == 0) {
		return nil
	}
	return &journalIdentity{Device: volume, File: indexHigh<<32 | indexLow}
}

func reflectedUint(value reflect.Value) (uint64, bool) {
	if !value.IsValid() {
		return 0, false
	}
	switch value.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := value.Int()
		if integer < 0 {
			return 0, false
		}
		return uint64(integer), true
	default:
		return 0, false
	}
}

func (j *transactionJournal) ensureRoot() error {
	if j.root != nil {
		return nil
	}
	root, err := os.OpenRoot(j.manifest.Root)
	if err != nil {
		return err
	}
	j.root = root
	return nil
}

func (j *transactionJournal) ensureInternal() error {
	if err := j.ensureRoot(); err != nil {
		return err
	}
	for _, name := range []string{j.manifest.Internal, filepath.Join(j.manifest.Internal, "staged"), filepath.Join(j.manifest.Internal, "moved")} {
		if err := j.root.MkdirAll(name, 0o700); err != nil {
			return err
		}
		info, err := j.root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("storage/fs: invalid internal transaction directory: %w", storage.ErrConflict)
		}
	}
	return nil
}

func (j *transactionJournal) entryAt(relative string) (entry journalEntry, info fs.FileInfo, exists bool, err error) {
	if err := j.ensureRoot(); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return journalEntry{}, nil, false, nil
		}
		return journalEntry{}, nil, false, err
	}
	info, err = j.root.Lstat(relative)
	if errors.Is(err, fs.ErrNotExist) {
		return journalEntry{}, nil, false, nil
	}
	if err != nil {
		return journalEntry{}, nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return journalEntry{}, nil, false, fmt.Errorf("storage/fs: transaction path became a symbolic link: %s", relative)
	}
	entry = journalEntry{Directory: info.IsDir(), Mode: uint32(info.Mode().Perm()), Size: info.Size(), Identity: journalIdentityFromInfo(info)}
	if info.IsDir() {
		return entry, info, true, nil
	}
	if !info.Mode().IsRegular() {
		return journalEntry{}, nil, false, fmt.Errorf("storage/fs: transaction path is not regular: %s", relative)
	}
	file, err := openRootRegular(j.root, relative)
	if err != nil {
		return journalEntry{}, nil, false, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	openedInfo, err := file.Stat()
	if err != nil {
		return journalEntry{}, nil, false, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return journalEntry{}, nil, false, fmt.Errorf("storage/fs: transaction path changed while opening: %s", relative)
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, file)
	if err != nil {
		return journalEntry{}, nil, false, err
	}
	entry.Size = read
	entry.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	return entry, openedInfo, true, nil
}

func (j *transactionJournal) backupRootFile(relative, destination string, expected fs.FileInfo) (err error) {
	if err := j.ensureRoot(); err != nil {
		return err
	}
	file, err := openRootRegular(j.root, relative)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(expected, openedInfo) {
		return fmt.Errorf("storage/fs: backup source identity changed: %w", storage.ErrConflict)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, openedInfo.Mode().Perm())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	if _, err := io.Copy(output, file); err != nil {
		return err
	}
	return output.Sync()
}

func (j *transactionJournal) markApplied(index int, relative string, expected fs.FileInfo) error {
	_, info, exists, err := j.entryAt(relative)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("storage/fs: installed path disappeared: %w", storage.ErrConflict)
	}
	if expected != nil && !os.SameFile(expected, info) {
		return fmt.Errorf("storage/fs: installed path identity changed before journaling: %w", storage.ErrConflict)
	}
	if j.installed == nil {
		j.installed = make(map[int]fs.FileInfo)
	}
	j.installed[index] = info
	action := &j.manifest.Actions[index]
	action.Applied = true
	if action.Desired != nil {
		action.Desired.Identity = journalIdentityFromInfo(info)
	}
	return j.persist()
}

func (j *transactionJournal) markDeleted(index int) error {
	j.manifest.Actions[index].Applied = true
	return j.persist()
}

func (j *transactionJournal) stageFile(index int, data []byte, mode fs.FileMode) (relative string, info fs.FileInfo, err error) {
	if err := j.ensureInternal(); err != nil {
		return "", nil, err
	}
	relative = filepath.Join(j.manifest.Internal, "staged", fmt.Sprintf("%06d", index))
	file, err := j.root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := file.Chmod(mode); err != nil {
		return "", nil, err
	}
	if _, err := file.Write(data); err != nil {
		return "", nil, err
	}
	if err := file.Sync(); err != nil {
		return "", nil, err
	}
	info, err = file.Stat()
	if err != nil {
		return "", nil, err
	}
	action := &j.manifest.Actions[index]
	action.Staged = relative
	if action.Desired != nil {
		action.Desired.Identity = journalIdentityFromInfo(info)
	}
	if err := j.persist(); err != nil {
		return "", nil, err
	}
	return relative, info, nil
}

func (j *transactionJournal) stageRestoration(index int, data []byte, mode fs.FileMode) (relative string, info fs.FileInfo, err error) {
	if err := j.ensureInternal(); err != nil {
		return "", nil, err
	}
	action := &j.manifest.Actions[index]
	if action.RestoreStage == "" {
		relative = filepath.Join(j.manifest.Internal, "staged", fmt.Sprintf("restore-%06d", index))
		restoring := *action.Original
		restoring.Identity = nil
		action.Restoring = &restoring
		action.RestoreStage = relative
		if err := j.persist(); err != nil {
			return "", nil, err
		}
	} else {
		relative = action.RestoreStage
	}
	if current, currentInfo, exists, inspectErr := j.entryAt(relative); inspectErr != nil {
		return "", nil, inspectErr
	} else if exists {
		if action.Restoring != nil && action.Restoring.Identity != nil {
			if journalEntriesEqual(current, *action.Restoring) && journalIdentitiesEqual(current.Identity, action.Restoring.Identity) {
				return relative, currentInfo, nil
			}
			return "", nil, fmt.Errorf("storage/fs: restoration stage identity changed: %w", storage.ErrConflict)
		}
		// A crash before identity persistence can leave a partial private stage.
		// It has never been installed, so remove it and recreate deterministically.
		if err := j.root.RemoveAll(relative); err != nil {
			return "", nil, err
		}
	}
	file, err := j.root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := file.Chmod(mode); err != nil {
		return "", nil, err
	}
	if _, err := file.Write(data); err != nil {
		return "", nil, err
	}
	if err := file.Sync(); err != nil {
		return "", nil, err
	}
	info, err = file.Stat()
	if err != nil {
		return "", nil, err
	}
	action = &j.manifest.Actions[index]
	action.Restoring.Identity = journalIdentityFromInfo(info)
	if err := j.persist(); err != nil {
		return "", nil, err
	}
	return relative, info, nil
}

func (j *transactionJournal) stageDirectory(index int, mode fs.FileMode) (string, fs.FileInfo, error) {
	if err := j.ensureInternal(); err != nil {
		return "", nil, err
	}
	relative := filepath.Join(j.manifest.Internal, "staged", fmt.Sprintf("%06d", index))
	if err := j.root.Mkdir(relative, mode); err != nil {
		return "", nil, err
	}
	info, err := j.root.Lstat(relative)
	if err != nil {
		return "", nil, err
	}
	action := &j.manifest.Actions[index]
	action.Staged = relative
	if action.Desired != nil {
		action.Desired.Identity = journalIdentityFromInfo(info)
	}
	if err := j.persist(); err != nil {
		return "", nil, err
	}
	return relative, info, nil
}

func (j *transactionJournal) prepareMove(index int) (string, error) {
	if err := j.ensureInternal(); err != nil {
		return "", err
	}
	relative := filepath.Join(j.manifest.Internal, "moved", fmt.Sprintf("%06d", index))
	j.manifest.Actions[index].Moved = relative
	if err := j.persist(); err != nil {
		return "", err
	}
	return relative, nil
}

func (j *transactionJournal) addDirectory(relative string, desired treeEntry) error {
	if relative == "." {
		return j.addRootDirectory(desired)
	}
	if _, _, exists, err := j.entryAt(relative); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	}
	actionIndex, err := j.record(relative, nil, &desired)
	if err != nil {
		return err
	}
	staged, stagedInfo, err := j.stageDirectory(actionIndex, desired.mode)
	if err != nil {
		return err
	}
	if _, _, exists, err := j.entryAt(relative); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	}
	if err := j.root.Rename(staged, relative); err != nil {
		return err
	}
	j.addParent(filepath.Join(j.manifest.Root, relative))
	return j.markApplied(actionIndex, relative, stagedInfo)
}

func (j *transactionJournal) addRootDirectory(desired treeEntry) error {
	if _, err := os.Lstat(j.manifest.Root); err == nil {
		return fmt.Errorf("storage/fs: PKI root appeared: %w", storage.ErrConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	actionIndex, err := j.record(".", nil, &desired)
	if err != nil {
		return err
	}
	staged := filepath.Join(j.path, "root-staged")
	if err := os.Mkdir(staged, desired.mode); err != nil {
		return err
	}
	stagedInfo, err := os.Lstat(staged)
	if err != nil {
		return err
	}
	action := &j.manifest.Actions[actionIndex]
	action.Staged = staged
	action.Desired.Identity = journalIdentityFromInfo(stagedInfo)
	j.manifest.RootIdentity = action.Desired.Identity
	if err := j.persist(); err != nil {
		return err
	}
	if err := os.Rename(staged, j.manifest.Root); err != nil {
		return err
	}
	if err := j.ensureRoot(); err != nil {
		return err
	}
	j.addParent(j.manifest.Root)
	return j.markApplied(actionIndex, ".", stagedInfo)
}

func (j *transactionJournal) verifyEntry(relative string, expected treeEntry) error {
	current, info, exists, err := j.entryAt(relative)
	if err != nil {
		return err
	}
	if !exists || current.Directory != expected.isDir || current.Mode != uint32(expected.mode.Perm()) ||
		(!expected.isDir && (current.Size != expected.size || current.SHA256 != hex.EncodeToString(expected.hash[:]))) ||
		!os.SameFile(expected.info, info) {
		return fmt.Errorf("storage/fs: path changed before commit %s: %w", relative, storage.ErrConflict)
	}
	return nil
}

func (j *transactionJournal) chmodDirectory(relative string, original, desired treeEntry) error {
	if err := j.verifyEntry(relative, original); err != nil {
		return err
	}
	actionIndex, err := j.record(relative, &original, &desired)
	if err != nil {
		return err
	}
	// chmod keeps the same directory identity, so persist the expected identity
	// before the operation to make the crash window recoverable.
	j.manifest.Actions[actionIndex].Desired.Identity = journalIdentityFromInfo(original.info)
	if err := j.persist(); err != nil {
		return err
	}
	if err := j.verifyEntry(relative, original); err != nil {
		return err
	}
	directory, err := j.root.Open(relative)
	if err != nil {
		return err
	}
	openedInfo, statErr := directory.Stat()
	if statErr != nil || !openedInfo.IsDir() || !os.SameFile(original.info, openedInfo) {
		_ = directory.Close()
		return errors.Join(statErr, fmt.Errorf("storage/fs: directory identity changed before chmod: %w", storage.ErrConflict))
	}
	chmodErr := directory.Chmod(desired.mode)
	closeErr := directory.Close()
	if err := errors.Join(chmodErr, closeErr); err != nil {
		return err
	}
	j.addParent(filepath.Join(j.manifest.Root, relative))
	return j.markApplied(actionIndex, relative, original.info)
}

func (j *transactionJournal) writeFile(relative string, original *treeEntry, source string, desired treeEntry) error {
	if original != nil {
		if err := j.verifyEntry(relative, *original); err != nil {
			return err
		}
	} else if _, _, exists, err := j.entryAt(relative); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	}
	actionIndex, err := j.record(relative, original, &desired)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if sha256.Sum256(data) != desired.hash {
		return fmt.Errorf("storage/fs: staged file changed before commit: %s", relative)
	}
	staged, stagedInfo, err := j.stageFile(actionIndex, data, desired.mode)
	if err != nil {
		return err
	}
	if original != nil {
		if err := j.verifyEntry(relative, *original); err != nil {
			return err
		}
	} else if _, _, exists, err := j.entryAt(relative); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("storage/fs: destination appeared %s: %w", relative, storage.ErrConflict)
	}
	if err := j.root.Rename(staged, relative); err != nil {
		return err
	}
	parent := filepath.Dir(filepath.Join(j.manifest.Root, relative))
	j.addParent(filepath.Join(j.manifest.Root, relative))
	syncErr := syncDirectory(parent)
	current, currentInfo, exists, inspectErr := j.entryAt(relative)
	installed := exists && journalEntriesEqual(current, *j.manifest.Actions[actionIndex].Desired) && os.SameFile(stagedInfo, currentInfo)
	if !installed {
		return errors.Join(syncErr, inspectErr, fmt.Errorf("storage/fs: transaction write identity was not installed: %s", relative))
	}
	return errors.Join(syncErr, j.markApplied(actionIndex, relative, stagedInfo))
}

func (j *transactionJournal) deleteFile(relative string, original treeEntry) error {
	return j.deletePath(relative, original)
}

func (j *transactionJournal) deleteDirectory(relative string, original treeEntry) error {
	return j.deletePath(relative, original)
}

func (j *transactionJournal) deletePath(relative string, original treeEntry) error {
	if err := j.verifyEntry(relative, original); err != nil {
		return err
	}
	actionIndex, err := j.record(relative, &original, nil)
	if err != nil {
		return err
	}
	moved, err := j.prepareMove(actionIndex)
	if err != nil {
		return err
	}
	if err := j.verifyEntry(relative, original); err != nil {
		return err
	}
	if err := j.root.Rename(relative, moved); err != nil {
		return err
	}
	movedInfo, err := j.root.Lstat(moved)
	if err != nil {
		return err
	}
	if !os.SameFile(original.info, movedInfo) {
		return fmt.Errorf("storage/fs: moved path identity changed: %w", storage.ErrConflict)
	}
	if j.moved == nil {
		j.moved = make(map[int]fs.FileInfo)
	}
	j.moved[actionIndex] = movedInfo
	j.addParent(filepath.Join(j.manifest.Root, relative))
	return j.markDeleted(actionIndex)
}

func (j *transactionJournal) markCommitted() error {
	j.manifest.State = journalStateCommitted
	return j.persist()
}

func (j *transactionJournal) rollback() error {
	var rollbackErrors []error
	for i := len(j.manifest.Actions) - 1; i >= 0; i-- {
		rollbackErrors = append(rollbackErrors, j.rollbackAction(i, j.manifest.Actions[i]))
	}
	rollbackErrors = append(rollbackErrors, j.syncParents())
	return errors.Join(rollbackErrors...)
}

func (j *transactionJournal) rollbackAction(index int, action journalAction) error {
	current, _, exists, err := j.entryAt(action.Relative)
	if err != nil {
		return err
	}
	if exists && action.Restoring != nil && journalEntriesEqual(current, *action.Restoring) && journalIdentitiesEqual(current.Identity, action.Restoring.Identity) {
		return j.finishRestoration(index, current.Identity)
	}
	originalContent := exists && action.Original != nil && journalEntriesEqual(current, *action.Original)
	originalIdentity := originalContent && journalIdentitiesEqual(current.Identity, action.Original.Identity)
	desiredContent := exists && action.Desired != nil && journalEntriesEqual(current, *action.Desired)
	desiredIdentity := desiredContent && j.installedIdentityMatches(index, action.Relative, current, action)

	switch {
	case originalIdentity:
		return j.cleanupStaged(action)
	case !action.Applied && originalContent:
		return j.cleanupStaged(action) // Leaving an indistinguishable replacement is safe.
	case action.Original == nil && !exists:
		return j.cleanupStaged(action)
	case action.Desired == nil && !exists:
		return j.restoreOriginal(index, action)
	case desiredIdentity && action.Original == nil:
		return j.removeAdded(action)
	case desiredIdentity:
		return j.restoreOriginal(index, action)
	default:
		return fmt.Errorf("storage/fs: rollback path identity changed %s: %w", action.Relative, storage.ErrConflict)
	}
}

func (j *transactionJournal) finishRestoration(index int, identity *journalIdentity) error {
	action := &j.manifest.Actions[index]
	action.Original.Identity = identity
	action.Applied = false
	action.Staged = ""
	action.Restoring = nil
	action.RestoreStage = ""
	return j.persist()
}

func (j *transactionJournal) installedIdentityMatches(index int, relative string, current journalEntry, action journalAction) bool {
	if installed, ok := j.installed[index]; ok {
		_, info, exists, err := j.entryAt(relative)
		return err == nil && exists && os.SameFile(installed, info)
	}
	return action.Desired != nil && journalIdentitiesEqual(current.Identity, action.Desired.Identity)
}

func journalIdentitiesEqual(left, right *journalIdentity) bool {
	return left != nil && right != nil && left.Device == right.Device && left.File == right.File
}

func (j *transactionJournal) cleanupStaged(action journalAction) error {
	if action.Staged == "" {
		return nil
	}
	if filepath.IsAbs(action.Staged) {
		info, err := os.Lstat(action.Staged)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if action.Desired == nil || !journalIdentitiesEqual(journalIdentityFromInfo(info), action.Desired.Identity) {
			return fmt.Errorf("storage/fs: staged root identity changed: %w", storage.ErrConflict)
		}
		return os.RemoveAll(action.Staged)
	}
	if err := j.ensureRoot(); err != nil {
		return err
	}
	info, err := j.root.Lstat(action.Staged)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if action.Desired == nil || !journalIdentitiesEqual(journalIdentityFromInfo(info), action.Desired.Identity) {
		return fmt.Errorf("storage/fs: staged path identity changed: %w", storage.ErrConflict)
	}
	return j.root.RemoveAll(action.Staged)
}

func (j *transactionJournal) removeAdded(action journalAction) (err error) {
	if action.Relative == "." {
		parentPath := filepath.Dir(j.manifest.Root)
		parent, err := os.OpenRoot(parentPath)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, parent.Close()) }()
		rootName := filepath.Base(j.manifest.Root)
		currentInfo, err := parent.Lstat(rootName)
		if err != nil {
			return err
		}
		if action.Desired == nil || !journalIdentitiesEqual(journalIdentityFromInfo(currentInfo), action.Desired.Identity) {
			return fmt.Errorf("storage/fs: added root identity changed: %w", storage.ErrConflict)
		}
		if j.root != nil {
			if err := j.root.Close(); err != nil {
				return err
			}
			j.root = nil
		}
		destination := filepath.Join(filepath.Base(j.path), "rolled-back-root")
		if err := parent.Rename(rootName, destination); err != nil {
			return err
		}
		j.addParent(j.manifest.Root)
		return nil
	}
	if err := j.root.Remove(action.Relative); err != nil {
		return err
	}
	j.addParent(filepath.Join(j.manifest.Root, action.Relative))
	return j.cleanupStaged(action)
}

func (j *transactionJournal) restoreOriginal(index int, action journalAction) error {
	if action.Original == nil {
		return nil
	}
	if action.Moved != "" {
		if err := j.ensureRoot(); err != nil {
			return err
		}
		movedInfo, err := j.root.Lstat(action.Moved)
		if err != nil {
			return err
		}
		if transient, ok := j.moved[index]; ok {
			if !os.SameFile(transient, movedInfo) {
				return fmt.Errorf("storage/fs: moved rollback identity changed: %w", storage.ErrConflict)
			}
		} else if !journalIdentitiesEqual(journalIdentityFromInfo(movedInfo), action.Original.Identity) {
			return fmt.Errorf("storage/fs: moved rollback identity unavailable: %w", storage.ErrConflict)
		}
		if _, _, exists, err := j.entryAt(action.Relative); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("storage/fs: rollback destination appeared: %w", storage.ErrConflict)
		}
		if err := j.root.Rename(action.Moved, action.Relative); err != nil {
			return err
		}
		j.addParent(filepath.Join(j.manifest.Root, action.Relative))
		restored := &j.manifest.Actions[index]
		restored.Applied = false
		restored.Moved = ""
		return j.persist()
	}
	if action.Original.Directory {
		directory, err := j.root.Open(action.Relative)
		if err != nil {
			return err
		}
		chmodErr := directory.Chmod(fs.FileMode(action.Original.Mode))
		closeErr := directory.Close()
		return errors.Join(chmodErr, closeErr)
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
	staged, stagedInfo, err := j.stageRestoration(index, data, fs.FileMode(action.Original.Mode))
	if err != nil {
		return err
	}
	action = j.manifest.Actions[index]
	if err := j.root.Rename(staged, action.Relative); err != nil {
		return err
	}
	current, restoredInfo, exists, err := j.entryAt(action.Relative)
	if err != nil || !exists || !os.SameFile(stagedInfo, restoredInfo) || action.Restoring == nil || !journalEntriesEqual(current, *action.Restoring) {
		return errors.Join(err, fmt.Errorf("storage/fs: restored file identity mismatch: %w", storage.ErrConflict))
	}
	j.addParent(filepath.Join(j.manifest.Root, action.Relative))
	return j.finishRestoration(index, journalIdentityFromInfo(restoredInfo))
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
	var cleanupErrors []error
	if j.root != nil {
		cleanupErrors = append(cleanupErrors, j.root.RemoveAll(j.manifest.Internal), j.root.Close())
		j.root = nil
	}
	cleanupErrors = append(cleanupErrors, os.RemoveAll(j.path), syncDirectory(filepath.Dir(j.path)))
	return errors.Join(cleanupErrors...)
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
	journal := &transactionJournal{path: path, manifest: manifest}
	if root, openErr := os.OpenRoot(manifest.Root); openErr == nil {
		openedInfo, statErr := root.Stat(".")
		if statErr != nil || !journalIdentitiesEqual(journalIdentityFromInfo(openedInfo), manifest.RootIdentity) {
			_ = root.Close()
			return nil, errors.Join(statErr, fmt.Errorf("storage/fs: recovery root identity changed: %w", storage.ErrConflict))
		}
		journal.root = root
	} else if errors.Is(openErr, fs.ErrNotExist) {
		validAbsentRoot := manifest.RootInitiallyAbsent && manifest.State == journalStatePrepared
		if len(manifest.Actions) > 0 && (manifest.Actions[0].Relative != "." || manifest.Actions[0].Original != nil) {
			validAbsentRoot = false
		}
		if !validAbsentRoot {
			return nil, fmt.Errorf("storage/fs: recovery root disappeared: %w", storage.ErrConflict)
		}
	} else {
		return nil, openErr
	}
	return journal, nil
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
		if err := validateJournalActions(path, journal.manifest.Internal, journal.manifest.Actions); err != nil {
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

func validateJournalActions(journalPath, internal string, actions []journalAction) error {
	if internal == "" || filepath.IsAbs(internal) || filepath.Base(internal) != internal || !strings.HasPrefix(internal, ".go-easyrsa-txn-") {
		return fmt.Errorf("invalid internal transaction directory %q", internal)
	}
	for _, action := range actions {
		if action.Relative != "." {
			if err := validateRelativeTreePath(action.Relative); err != nil {
				return err
			}
		}
		if action.Backup != "" {
			clean := filepath.Clean(action.Backup)
			if filepath.IsAbs(clean) || clean == "backups" || !strings.HasPrefix(clean, "backups"+string(filepath.Separator)) {
				return fmt.Errorf("backup path escaped journal: %s", action.Backup)
			}
		}
		if action.Staged != "" {
			clean := filepath.Clean(action.Staged)
			validRootStage := filepath.IsAbs(clean) && filepath.Dir(clean) == journalPath
			validInternalStage := !filepath.IsAbs(clean) && strings.HasPrefix(clean, filepath.Join(internal, "staged")+string(filepath.Separator))
			if !validRootStage && !validInternalStage {
				return fmt.Errorf("staged path escaped transaction: %s", action.Staged)
			}
		}
		if action.RestoreStage != "" {
			clean := filepath.Clean(action.RestoreStage)
			if filepath.IsAbs(clean) || !strings.HasPrefix(clean, filepath.Join(internal, "staged")+string(filepath.Separator)) {
				return fmt.Errorf("restoration path escaped transaction: %s", action.RestoreStage)
			}
		}
		if action.Moved != "" {
			clean := filepath.Clean(action.Moved)
			if filepath.IsAbs(clean) || !strings.HasPrefix(clean, filepath.Join(internal, "moved")+string(filepath.Separator)) {
				return fmt.Errorf("moved path escaped transaction: %s", action.Moved)
			}
		}
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

func syncDirectory(path string) (err error) {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	if err := directory.Sync(); err != nil {
		if runtime.GOOS == "windows" || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
		return err
	}
	return nil
}
