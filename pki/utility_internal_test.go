package pki

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type failingRandomReader struct{ err error }

func (r failingRandomReader) Read([]byte) (int, error) { return 0, r.err }

func TestCloneDNSequenceDeepCopiesBitStrings(t *testing.T) {
	t.Parallel()

	shared := []byte{1, 2, 3}
	sequence := pkix.RDNSequence{{
		{Type: asn1.ObjectIdentifier{1, 2, 3}, Value: asn1.BitString{Bytes: shared, BitLength: 24}},
		{Type: asn1.ObjectIdentifier{1, 2, 4}, Value: asn1.BitString{Bytes: shared, BitLength: 24}},
	}}
	cloned := cloneDNSequence(sequence)
	first := cloned[0][0].Value.(asn1.BitString)
	first.Bytes[0] = 9
	first.Bytes = append(first.Bytes, 4)
	cloned[0][0].Value = first
	require.Equal(t, []byte{1, 2, 3}, shared)
	require.Equal(t, []byte{1, 2, 3}, cloned[0][1].Value.(asn1.BitString).Bytes)
}

func TestReadRegularPathRejectsDescriptorReplacement(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	name := filepath.Join(directory, "input")
	replacement := filepath.Join(directory, "replacement")
	require.NoError(t, os.WriteFile(name, []byte("original"), 0o600))
	require.NoError(t, os.WriteFile(replacement, []byte("replacement"), 0o600))
	_, _, err := readRegularPathWith(name, func(path string) (*os.File, error) {
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		if err := os.Rename(replacement, path); err != nil {
			return nil, err
		}
		return os.Open(path)
	})
	require.Error(t, err)
}

func TestRandPropagatesShortEntropySource(t *testing.T) {
	t.Parallel()

	pk, err := NewWithMemory(Config{})
	require.NoError(t, err)
	pk.random = bytes.NewReader([]byte{1})
	err = pk.Rand(2, io.Discard)
	require.ErrorIs(t, err, io.EOF)
}

func TestRandPropagatesEntropyFailure(t *testing.T) {
	t.Parallel()

	pk, err := NewWithMemory(Config{})
	require.NoError(t, err)
	entropyErr := errors.New("entropy unavailable")
	pk.random = failingRandomReader{err: entropyErr}
	err = pk.Rand(16, io.Discard)
	require.ErrorIs(t, err, entropyErr)
}
