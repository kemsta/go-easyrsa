package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	fsstore "github.com/kemsta/go-easyrsa/v2/storage/fs"
)

func TestCLI_MigratesLegacyToFS(t *testing.T) {
	sourceDir := t.TempDir()
	fixture := testutil.WriteLegacyFixture(t, sourceDir)
	targetDir := t.TempDir()

	out, err := runCLI(t, "--from", sourceDir, "--to", targetDir)
	if err != nil {
		t.Fatalf("Execute: %v\nOutput:\n%s", err, out)
	}

	target, err := pki.NewWithFS(targetDir, pki.Config{})
	if err != nil {
		t.Fatalf("NewWithFS: %v", err)
	}
	pair, err := target.ShowCert("client1")
	if err != nil {
		t.Fatalf("ShowCert: %v", err)
	}
	serial, err := pair.Serial()
	if err != nil {
		t.Fatalf("Serial: %v", err)
	}
	if serial.Cmp(testutil.MustSerial(t, fixture.ClientCurrent)) != 0 {
		t.Fatalf("unexpected latest serial: got %s want %s", serial.Text(16), testutil.MustSerial(t, fixture.ClientCurrent).Text(16))
	}
}

func TestCLI_RejectsNonEmptyTarget(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)
	targetDir := t.TempDir()
	testutil.WriteLegacyFixture(t, targetDir)

	_, err := runCLI(t, "--from", sourceDir, "--to", targetDir)
	if err == nil {
		t.Fatal("expected error for non-empty target")
	}
}

func TestCLI_RejectsUnknownFromType(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)
	targetDir := t.TempDir()

	_, err := runCLI(t, "--from", sourceDir, "--to", targetDir, "--from-type", "wat")
	if err == nil {
		t.Fatal("expected error for unknown from-type")
	}
}

func TestCLI_RejectsUnknownToType(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)
	targetDir := t.TempDir()

	_, err := runCLI(t, "--from", sourceDir, "--to", targetDir, "--to-type", "wat")
	if err == nil {
		t.Fatal("expected error for unknown to-type")
	}
}

func TestCLI_RejectsSameSourceAndTarget(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteLegacyFixture(t, dir)

	_, err := runCLI(t, "--from", dir, "--to", dir)
	if err == nil {
		t.Fatal("expected error for same source and target")
	}
}

func TestCLI_MigratesWithoutCRL(t *testing.T) {
	sourceDir := t.TempDir()
	testutil.WriteLegacyFixture(t, sourceDir)
	if err := os.Remove(filepath.Join(sourceDir, "crl.pem")); err != nil {
		t.Fatalf("Remove crl.pem: %v", err)
	}
	targetDir := t.TempDir()

	out, err := runCLI(t, "--from", sourceDir, "--to", targetDir)
	if err != nil {
		t.Fatalf("Execute: %v\nOutput:\n%s", err, out)
	}

	crl, err := fsstore.NewCRLHolder(targetDir).Get()
	if err != nil {
		t.Fatalf("Get CRL: %v", err)
	}
	if len(crl.Raw) != 0 {
		t.Fatalf("expected empty CRL after migrating source without crl.pem")
	}
}
