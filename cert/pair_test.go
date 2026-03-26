package cert_test

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage/memory"
)

func newTestPKI(t *testing.T) *pki.PKI {
	t.Helper()
	ks, cs, idx, sp, crl := memory.New()
	pk, err := pki.New(pki.Config{NoPass: true}, ks, cs, idx, sp, crl)
	require.NoError(t, err)
	return pk
}

func requirePrivateKey[T any](t *testing.T, key crypto.PrivateKey) T {
	t.Helper()
	typed, ok := key.(T)
	require.Truef(t, ok, "expected private key type %T, got %T", *new(T), key)
	return typed
}

func TestPair_PublicHelpersAcrossCertTypes(t *testing.T) {
	pk := newTestPKI(t)

	caPair, err := pk.BuildCA()
	require.NoError(t, err)
	clientPair, err := pk.BuildClientFull("client1")
	require.NoError(t, err)
	serverPair, err := pk.BuildServerFull("server1")
	require.NoError(t, err)
	serverClientPair, err := pk.BuildServerClientFull("sc1")
	require.NoError(t, err)

	tests := []struct {
		name     string
		pair     *certpkg.Pair
		wantType certpkg.CertType
		wantCA   bool
	}{
		{name: "ca", pair: caPair, wantType: certpkg.CertTypeCA, wantCA: true},
		{name: "client", pair: clientPair, wantType: certpkg.CertTypeClient, wantCA: false},
		{name: "server", pair: serverPair, wantType: certpkg.CertTypeServer, wantCA: false},
		{name: "server-client", pair: serverClientPair, wantType: certpkg.CertTypeServerClient, wantCA: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			crt, err := tc.pair.Certificate()
			require.NoError(t, err)
			require.NotNil(t, crt)

			serial, err := tc.pair.Serial()
			require.NoError(t, err)
			assert.Zero(t, serial.Cmp(crt.SerialNumber))

			certType, err := tc.pair.CertType()
			require.NoError(t, err)
			assert.Equal(t, tc.wantType, certType)

			isCA, err := tc.pair.IsCA()
			require.NoError(t, err)
			assert.Equal(t, tc.wantCA, isCA)

			assert.True(t, tc.pair.HasKey())
			key, err := tc.pair.PrivateKey()
			require.NoError(t, err)
			require.NotNil(t, key)
			requirePrivateKey[crypto.Signer](t, key)
		})
	}
}

func TestPair_CertificateAndSerialErrors(t *testing.T) {
	pair := &certpkg.Pair{Name: "broken", CertPEM: []byte("not a cert")}

	_, err := pair.Certificate()
	assert.Error(t, err)

	_, err = pair.Serial()
	assert.Error(t, err)

	_, err = pair.CertType()
	assert.Error(t, err)

	_, err = pair.IsCA()
	assert.Error(t, err)
}

func TestPair_PrivateKeyErrorsAndHasKey(t *testing.T) {
	t.Run("missing key", func(t *testing.T) {
		pair := &certpkg.Pair{Name: "nokey"}
		assert.False(t, pair.HasKey())
		_, err := pair.PrivateKey()
		assert.Error(t, err)
	})

	t.Run("bad key pem", func(t *testing.T) {
		pair := &certpkg.Pair{Name: "badkey", KeyPEM: []byte("not a key")}
		assert.True(t, pair.HasKey())
		_, err := pair.PrivateKey()
		assert.Error(t, err)
	})
}

func TestPair_CertTypeReturnsErrorForUnrecognizedEKU(t *testing.T) {
	pk := newTestPKI(t)
	_, err := pk.BuildCA()
	require.NoError(t, err)

	pair, err := pk.BuildClientFull("codesign", pki.WithCertModifier(func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}))
	require.NoError(t, err)

	certType, err := pair.CertType()
	assert.Error(t, err)
	assert.NotEqual(t, certpkg.CertTypeClient, certType)
}
