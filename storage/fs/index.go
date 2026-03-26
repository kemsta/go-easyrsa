package fs

import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// indexTimeFormat is the UTCTime format used in index.txt (yyMMddHHmmssZ).
const indexTimeFormat = "060102150405Z"

// IndexDB implements storage.IndexDB using an OpenSSL-compatible index.txt file.
// Concurrent access within the same process is serialized by mu.
type IndexDB struct {
	path string
	mu   sync.RWMutex
}

// NewIndexDB creates an IndexDB backed by pkiDir/index.txt.
func NewIndexDB(pkiDir string) *IndexDB {
	return &IndexDB{path: fsJoin(pkiDir, "index.txt")}
}

func (db *IndexDB) Empty() (bool, error) { return OwnershipProbe{Dir: filepath.Dir(db.path)}.Empty() }
func (db *IndexDB) Owned() (bool, error) { return OwnershipProbe{Dir: filepath.Dir(db.path)}.Owned() }

func (db *IndexDB) Record(entry storage.IndexEntry) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	entries, err := db.readAll()
	if err != nil {
		return err
	}
	entries = append(entries, entry)
	return db.writeAll(entries)
}

func (db *IndexDB) Update(serial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	entries, err := db.readAll()
	if err != nil {
		return err
	}
	found := false
	for i, e := range entries {
		if e.Serial.Cmp(serial) == 0 {
			entries[i].Status = status
			if status == storage.StatusRevoked {
				entries[i].RevokedAt = revokedAt
				entries[i].RevocationReason = reason
			}
			found = true
			break
		}
	}
	if !found {
		return storage.ErrNotFound
	}
	return db.writeAll(entries)
}

func (db *IndexDB) RecordAndUpdate(newEntry storage.IndexEntry, oldSerial *big.Int, status storage.CertStatus, revokedAt time.Time, reason cert.RevocationReason) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	entries, err := db.readAll()
	if err != nil {
		return err
	}
	entries = append(entries, newEntry)
	for i, e := range entries {
		if e.Serial.Cmp(oldSerial) == 0 {
			entries[i].Status = status
			if status == storage.StatusRevoked {
				entries[i].RevokedAt = revokedAt
				entries[i].RevocationReason = reason
			}
			break
		}
	}
	// If oldSerial is not in the index (e.g. cert was created by an external
	// tool), we still commit the new entry; the old one simply remains untracked.
	return db.writeAll(entries)
}

func (db *IndexDB) Query(filter storage.IndexFilter) ([]storage.IndexEntry, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	entries, err := db.readAll()
	if err != nil {
		return nil, err
	}
	var result []storage.IndexEntry
	for _, e := range entries {
		if filter.Status != nil && e.Status != *filter.Status {
			continue
		}
		if filter.Name != "" && e.Subject.CommonName != filter.Name {
			continue
		}
		result = append(result, e)
	}
	return result, nil
}

// ReplaceAll replaces the entire index with the provided entries.
func (db *IndexDB) ReplaceAll(entries []storage.IndexEntry) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	cloned := make([]storage.IndexEntry, len(entries))
	for i, e := range entries {
		cloned[i] = e
		if e.Serial != nil {
			cloned[i].Serial = new(big.Int).Set(e.Serial)
		}
	}
	return db.writeAll(cloned)
}

func (db *IndexDB) readAll() ([]storage.IndexEntry, error) {
	f, err := os.Open(db.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []storage.IndexEntry
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}
		e, err := parseIndexLine(line)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("index.txt line %d: %w", lineNum, err)
		}
		entries = append(entries, e)
	}
	scanErr := scanner.Err()
	if closeErr := f.Close(); closeErr != nil && scanErr == nil {
		scanErr = closeErr
	}
	return entries, scanErr
}

func (db *IndexDB) writeAll(entries []storage.IndexEntry) error {
	var buf bytes.Buffer
	for _, e := range entries {
		fmt.Fprintln(&buf, formatIndexEntry(e))
	}
	return writeAtomic(db.path, buf.Bytes())
}

// writeAtomic writes data to path atomically: it writes to a temporary file in
// the same directory, fsyncs, then renames. On POSIX systems rename is atomic —
// either the old file is intact or the new file is fully written.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".idx-tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// formatIndexEntry formats an IndexEntry as an index.txt line.
func formatIndexEntry(e storage.IndexEntry) string {
	expires := e.ExpiresAt.UTC().Format(indexTimeFormat)
	serial := hexSerial(e.Serial)
	subject := subjectDNString(e.Subject)

	var revoked string
	if e.Status == storage.StatusRevoked {
		revoked = e.RevokedAt.UTC().Format(indexTimeFormat) + "," + reasonString(e.RevocationReason)
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\tunknown\t%s",
		string(e.Status), expires, revoked, serial, subject)
}

// parseIndexLine parses a single index.txt line into an IndexEntry.
func parseIndexLine(line string) (storage.IndexEntry, error) {
	fields := strings.SplitN(line, "\t", 6)
	if len(fields) < 6 {
		return storage.IndexEntry{}, fmt.Errorf("index: malformed line: %q", line)
	}

	status := storage.CertStatus(fields[0])
	expiresAt, err := time.ParseInLocation(indexTimeFormat, fields[1], time.UTC)
	if err != nil {
		return storage.IndexEntry{}, fmt.Errorf("index: bad expires %q: %w", fields[1], err)
	}

	var revokedAt time.Time
	var reason cert.RevocationReason
	if fields[2] != "" {
		parts := strings.SplitN(fields[2], ",", 2)
		revokedAt, err = time.ParseInLocation(indexTimeFormat, parts[0], time.UTC)
		if err != nil {
			return storage.IndexEntry{}, fmt.Errorf("index: bad revoked time %q: %w", parts[0], err)
		}
		if len(parts) > 1 {
			reason = parseReasonString(parts[1])
		}
	}

	serial := new(big.Int)
	if _, ok := serial.SetString(fields[3], 16); !ok {
		return storage.IndexEntry{}, fmt.Errorf("index: invalid serial %q", fields[3])
	}

	subject := parseDNString(fields[5])

	return storage.IndexEntry{
		Status:           status,
		ExpiresAt:        expiresAt,
		RevokedAt:        revokedAt,
		Serial:           serial,
		Subject:          subject,
		RevocationReason: reason,
	}, nil
}

// subjectDNString formats a pkix.Name as /CN=foo/O=bar etc.
func subjectDNString(n pkix.Name) string {
	var parts []string
	if n.CommonName != "" {
		parts = append(parts, "CN="+n.CommonName)
	}
	for _, v := range n.Organization {
		parts = append(parts, "O="+v)
	}
	for _, v := range n.OrganizationalUnit {
		parts = append(parts, "OU="+v)
	}
	for _, v := range n.Country {
		parts = append(parts, "C="+v)
	}
	for _, v := range n.Province {
		parts = append(parts, "ST="+v)
	}
	for _, v := range n.Locality {
		parts = append(parts, "L="+v)
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

// parseDNString parses /CN=foo/O=bar into a pkix.Name.
func parseDNString(s string) pkix.Name {
	var n pkix.Name
	if !strings.HasPrefix(s, "/") {
		return n
	}
	for _, part := range strings.Split(strings.TrimPrefix(s, "/"), "/") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "CN":
			n.CommonName = kv[1]
		case "O":
			n.Organization = append(n.Organization, kv[1])
		case "OU":
			n.OrganizationalUnit = append(n.OrganizationalUnit, kv[1])
		case "C":
			n.Country = append(n.Country, kv[1])
		case "ST":
			n.Province = append(n.Province, kv[1])
		case "L":
			n.Locality = append(n.Locality, kv[1])
		}
	}
	return n
}

func reasonString(r cert.RevocationReason) string {
	switch r {
	case cert.ReasonKeyCompromise:
		return "keyCompromise"
	case cert.ReasonCACompromise:
		return "caCompromise"
	case cert.ReasonAffiliationChanged:
		return "affiliationChanged"
	case cert.ReasonSuperseded:
		return "superseded"
	case cert.ReasonCessationOfOperation:
		return "cessationOfOperation"
	default:
		return "unspecified"
	}
}

func parseReasonString(s string) cert.RevocationReason {
	switch s {
	case "keyCompromise":
		return cert.ReasonKeyCompromise
	case "caCompromise":
		return cert.ReasonCACompromise
	case "affiliationChanged":
		return cert.ReasonAffiliationChanged
	case "superseded":
		return cert.ReasonSuperseded
	case "cessationOfOperation":
		return cert.ReasonCessationOfOperation
	default:
		return cert.ReasonUnspecified
	}
}
