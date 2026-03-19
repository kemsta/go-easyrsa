package fs_test

import (
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	fs "github.com/kemsta/go-easyrsa/storage/fs"

	"github.com/kemsta/go-easyrsa/storage"
)

// TestSerialProvider_Concurrent verifies that 20 goroutines calling Next()
// in parallel all receive unique serial numbers (no duplicate allocations).
func TestSerialProvider_Concurrent(t *testing.T) {
	dir := t.TempDir()
	sp := fs.NewSerialProvider(dir)

	const n = 20
	serials := make([]*big.Int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			s, err := sp.Next()
			if err != nil {
				t.Errorf("Next() error: %v", err)
				return
			}
			serials[i] = s
		}()
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for _, s := range serials {
		if s == nil {
			continue
		}
		key := s.Text(16)
		if seen[key] {
			t.Errorf("duplicate serial %s", key)
		}
		seen[key] = true
	}
}

// TestIndexDB_WriteAll_Idempotent records entries, updates one, and queries to
// confirm the temp+rename write path produces a correct result.
func TestIndexDB_WriteAll_Idempotent(t *testing.T) {
	dir := t.TempDir()
	db := fs.NewIndexDB(dir)
	sp := fs.NewSerialProvider(dir)

	s1, _ := sp.Next()
	s2, _ := sp.Next()
	s3, _ := sp.Next()

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.AddDate(1, 0, 0)

	for _, s := range []*big.Int{s1, s2, s3} {
		e := storage.IndexEntry{Status: storage.StatusValid, Serial: s, ExpiresAt: expires}
		if err := db.Record(e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	// Update s2 to revoked.
	if err := db.Update(s2, storage.StatusRevoked, now, 0); err != nil {
		t.Fatalf("Update: %v", err)
	}

	revokedStatus := storage.StatusRevoked
	results, err := db.Query(storage.IndexFilter{Status: &revokedStatus})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 || results[0].Serial.Cmp(s2) != 0 {
		t.Errorf("expected 1 revoked entry with serial %s, got %v", s2.Text(16), results)
	}
}

// TestParseIndexLine_InvalidSerial writes a line with an invalid hex serial
// directly to index.txt and verifies that Query skips it without error.
func TestParseIndexLine_InvalidSerial(t *testing.T) {
	dir := t.TempDir()
	db := fs.NewIndexDB(dir)

	// Write a line with an invalid (non-hex) serial directly into index.txt.
	badLine := "V\t310101000000Z\t\tZZZZNOTHEX\tunknown\t/CN=bad\n"
	if err := os.WriteFile(filepath.Join(dir, "index.txt"), []byte(badLine), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// readAll skips malformed lines — Query should return zero entries, no error.
	results, err := db.Query(storage.IndexFilter{})
	if err != nil {
		t.Fatalf("Query returned unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 entries after malformed line, got %d", len(results))
	}
}
