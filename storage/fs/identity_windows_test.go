//go:build windows

package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJournalIdentityAvailableOnWindows(t *testing.T) {
	name := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, os.WriteFile(name, []byte("data"), 0o600))
	info, err := os.Stat(name)
	require.NoError(t, err)
	identity := journalIdentityFromInfo(info)
	require.NotNil(t, identity)
	require.NotZero(t, identity.File)
}
