package testutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// DefaultBinary is the path to the easy-rsa binary relative to the module root.
const DefaultBinary = "subprojects/easy-rsa/easyrsa3/easyrsa"

// Runner executes easy-rsa commands for e2e tests.
type Runner struct {
	Binary string
	PKIDir string
	T      *testing.T
}

// moduleRoot walks up from the working directory to find the directory containing go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

// NewRunner creates a Runner. Uses the EASYRSA_BIN environment variable if set,
// otherwise looks for DefaultBinary relative to the module root.
// Skips the test if the binary is not found.
func NewRunner(t *testing.T, pkiDir string) *Runner {
	t.Helper()
	binary := os.Getenv("EASYRSA_BIN")
	if binary == "" {
		root, err := moduleRoot()
		if err != nil {
			t.Skipf("could not find module root: %v", err)
		}
		binary = filepath.Join(root, DefaultBinary)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("easy-rsa binary not found at %s (set EASYRSA_BIN to override): %v", binary, err)
	}
	return &Runner{
		Binary: binary,
		PKIDir: pkiDir,
		T:      t,
	}
}

// Run executes easy-rsa with EASYRSA_PKI and EASYRSA_BATCH set, prepending --batch.
// Calls t.Fatalf on non-zero exit. Returns combined stdout+stderr.
func (r *Runner) Run(args ...string) string {
	r.T.Helper()
	out, err := r.RunE(args...)
	if err != nil {
		r.T.Fatalf("easyrsa %v failed: %v\nOutput:\n%s", args, err, out)
	}
	return out
}

// RunE executes easy-rsa and returns combined output and error without failing the test.
func (r *Runner) RunE(args ...string) (string, error) {
	r.T.Helper()
	cmdArgs := append([]string{"--batch"}, args...)
	cmd := exec.Command(r.Binary, cmdArgs...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("EASYRSA_PKI=%s", r.PKIDir),
		"EASYRSA_BATCH=1",
	)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}
