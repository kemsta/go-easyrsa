package pkicrypto_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
)

func TestGenKey_RSA(t *testing.T) {
	key, err := pkicrypto.GenKey("rsa", 1024, nil)
	require.NoError(t, err)
	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok)
}

func TestGenKey_RSA_Default(t *testing.T) {
	key, err := pkicrypto.GenKey("", 0, nil)
	require.NoError(t, err)
	rsaKey, ok := key.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, 2048, rsaKey.N.BitLen())
}

func TestGenKey_ECDSA(t *testing.T) {
	key, err := pkicrypto.GenKey("ecdsa", 0, elliptic.P256())
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok)
}

func TestGenKey_ECDSA_DefaultCurve(t *testing.T) {
	key, err := pkicrypto.GenKey("ecdsa", 0, nil)
	require.NoError(t, err)
	ecKey, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256(), ecKey.Curve)
}

func TestGenKey_Ed25519(t *testing.T) {
	key, err := pkicrypto.GenKey("ed25519", 0, nil)
	require.NoError(t, err)
	_, ok := key.(ed25519.PrivateKey)
	assert.True(t, ok)
}

func TestMarshalUnmarshal_Roundtrip_NoPass(t *testing.T) {
	key, err := pkicrypto.GenKey("rsa", 1024, nil)
	require.NoError(t, err)

	pemBytes, err := pkicrypto.MarshalPrivateKey(key, "")
	require.NoError(t, err)
	assert.Contains(t, string(pemBytes), "PRIVATE KEY")

	recovered, err := pkicrypto.UnmarshalPrivateKey(pemBytes, "")
	require.NoError(t, err)
	assert.NotNil(t, recovered)
}

func TestMarshalUnmarshal_Roundtrip_WithPass(t *testing.T) {
	key, err := pkicrypto.GenKey("rsa", 1024, nil)
	require.NoError(t, err)

	pemBytes, err := pkicrypto.MarshalPrivateKey(key, "testpass")
	require.NoError(t, err)

	recovered, err := pkicrypto.UnmarshalPrivateKey(pemBytes, "testpass")
	require.NoError(t, err)
	assert.NotNil(t, recovered)
}

func TestUnmarshal_WrongPassphrase(t *testing.T) {
	key, err := pkicrypto.GenKey("rsa", 1024, nil)
	require.NoError(t, err)

	pemBytes, err := pkicrypto.MarshalPrivateKey(key, "correct")
	require.NoError(t, err)

	_, err = pkicrypto.UnmarshalPrivateKey(pemBytes, "wrong")
	assert.Error(t, err)
}

func TestUnmarshal_InvalidPEM(t *testing.T) {
	_, err := pkicrypto.UnmarshalPrivateKey([]byte("not pem"), "")
	assert.Error(t, err)
}

func TestPublicKey_RSA(t *testing.T) {
	key, _ := pkicrypto.GenKey("rsa", 1024, nil)
	pub, err := pkicrypto.PublicKey(key)
	require.NoError(t, err)
	_, ok := pub.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestPublicKey_ECDSA(t *testing.T) {
	key, _ := pkicrypto.GenKey("ecdsa", 0, nil)
	pub, err := pkicrypto.PublicKey(key)
	require.NoError(t, err)
	_, ok := pub.(*ecdsa.PublicKey)
	assert.True(t, ok)
}

func TestPublicKey_Ed25519(t *testing.T) {
	key, _ := pkicrypto.GenKey("ed25519", 0, nil)
	pub, err := pkicrypto.PublicKey(key)
	require.NoError(t, err)
	_, ok := pub.(ed25519.PublicKey)
	assert.True(t, ok)
}
