package testutil

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
)

func TestWriteLegacyFixture_WritesExpectedLegacyLayout(t *testing.T) {
	dir := t.TempDir()
	fixture := WriteLegacyFixture(t, dir)

	assert.Equal(t, dir, fixture.Dir)
	for _, tc := range []struct {
		name    string
		pair    *cert.Pair
		wantKey bool
	}{
		{name: "ca", pair: fixture.CAPair, wantKey: true},
		{name: "client-old", pair: fixture.ClientOld, wantKey: true},
		{name: "client-current", pair: fixture.ClientCurrent, wantKey: true},
		{name: "expired", pair: fixture.ExpiredPair, wantKey: true},
		{name: "revoked", pair: fixture.RevokedPair, wantKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serialHex := MustSerial(t, tc.pair).Text(16)
			certPath := filepath.Join(dir, tc.pair.Name, serialHex+".crt")
			certPEM, err := os.ReadFile(certPath)
			require.NoError(t, err)
			assert.Equal(t, tc.pair.CertPEM, certPEM)

			keyPath := filepath.Join(dir, tc.pair.Name, serialHex+".key")
			keyPEM, err := os.ReadFile(keyPath)
			if tc.wantKey {
				require.NoError(t, err)
				assert.Equal(t, tc.pair.KeyPEM, keyPEM)
			} else {
				assert.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}

	crlPEM, err := os.ReadFile(filepath.Join(dir, "crl.pem"))
	require.NoError(t, err)
	assert.Equal(t, fixture.CRLPEM, crlPEM)

	for _, keyPEM := range [][]byte{fixture.ClientOld.KeyPEM, fixture.ClientCurrent.KeyPEM} {
		block, _ := pem.Decode(keyPEM)
		require.NotNil(t, block)
		assert.Equal(t, "RSA PRIVATE KEY", block.Type)
	}
}

func TestMustSerial_ReturnsIndependentCopy(t *testing.T) {
	dir := t.TempDir()
	fixture := WriteLegacyFixture(t, dir)

	serial := MustSerial(t, fixture.ClientCurrent)
	serial.SetInt64(999)
	fresh := MustSerial(t, fixture.ClientCurrent)
	assert.NotZero(t, fresh.Cmp(serial))
}

