package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

func openFS(t *testing.T, dir string) *pki.PKI {
	t.Helper()
	pk, err := pki.NewWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)
	return pk
}

func hasNsCertType(t *testing.T, cert *x509.Certificate, want byte) bool {
	t.Helper()
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(legacyNsCertTypeOID) {
			continue
		}
		var bs asn1.BitString
		_, err := asn1.Unmarshal(ext.Value, &bs)
		require.NoError(t, err)
		return len(bs.Bytes) > 0 && bs.Bytes[0] == want
	}
	return false
}

func requireBackdatedLegacyWindow(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	require.True(t, cert.NotBefore.Before(time.Now().Add(-5*time.Minute)))
	require.Greater(t, cert.NotAfter.Sub(cert.NotBefore), time.Duration(98*365)*24*time.Hour)
}
