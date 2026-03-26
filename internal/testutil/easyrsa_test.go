package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildHelperBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	out := filepath.Join(dir, "helper")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}

	const program = `package main
import (
	"fmt"
	"os"
	"strings"
)
func main() {
	fmt.Printf("args=%s\n", strings.Join(os.Args[1:], ","))
	fmt.Printf("pki=%s\n", os.Getenv("EASYRSA_PKI"))
	fmt.Printf("batch=%s\n", os.Getenv("EASYRSA_BATCH"))
	if len(os.Args) > 0 && os.Args[len(os.Args)-1] == "fail" {
		os.Exit(3)
	}
}
`
	require.NoError(t, os.WriteFile(src, []byte(program), 0644))
	cmd := exec.Command("go", "build", "-o", out, src)
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "go build failed: %s", output)
	return out
}

func TestModuleRoot_FindsRepositoryRoot(t *testing.T) {
	root, err := moduleRoot()
	require.NoError(t, err)
	_, statErr := os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, statErr)
}

func TestNewRunnerRunE_UsesOverrideBinaryAndSetsEnv(t *testing.T) {
	binary := buildHelperBinary(t)
	t.Setenv("EASYRSA_BIN", binary)

	runner := NewRunner(t, "/tmp/pki-dir")
	out, err := runner.RunE("status")
	require.NoError(t, err)
	assert.Contains(t, out, "args=--batch,status")
	assert.Contains(t, out, "pki=/tmp/pki-dir")
	assert.Contains(t, out, "batch=1")
}

func TestRunnerRunE_ReturnsOutputOnFailure(t *testing.T) {
	binary := buildHelperBinary(t)
	t.Setenv("EASYRSA_BIN", binary)

	runner := NewRunner(t, "/tmp/pki-dir")
	out, err := runner.RunE("fail")
	require.Error(t, err)
	assert.Contains(t, out, "args=--batch,fail")
}

