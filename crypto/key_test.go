package pkicrypto_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
)

type encryptedPrivateKeyInfoFixture struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type pbes2ParamsFixture struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2ParamsFixture struct {
	Salt           []byte
	IterationCount int
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

var (
	oidPBES2Fixture      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2Fixture     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256Fixture = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBCFixture  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
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
	for _, algorithm := range []string{"rsa", "ecdsa", "ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			key, err := pkicrypto.GenKey(algorithm, 1024, elliptic.P256())
			require.NoError(t, err)

			pemBytes, err := pkicrypto.MarshalPrivateKey(key, "testpass")
			require.NoError(t, err)

			recovered, err := pkicrypto.UnmarshalPrivateKey(pemBytes, "testpass")
			require.NoError(t, err)
			assert.NotNil(t, recovered)
		})
	}
}

func TestMarshalPrivateKey_WithPassUsesEncryptedPKCS8(t *testing.T) {
	key, err := pkicrypto.GenKey("rsa", 1024, nil)
	require.NoError(t, err)

	pemBytes, err := pkicrypto.MarshalPrivateKey(key, "testpass")
	require.NoError(t, err)
	block, rest := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Empty(t, rest)
	assert.Equal(t, "ENCRYPTED PRIVATE KEY", block.Type)
	assert.False(t, x509.IsEncryptedPEMBlock(block)) //nolint:staticcheck // standard PKCS#8 is not legacy PEM encryption
}

func TestMarshalPrivateKey_UsesExpectedPBES2Profile(t *testing.T) {
	block := marshalEncryptedPKCS8Block(t)
	info := decodeEncryptedPKCS8Info(t, block.Bytes)
	require.True(t, info.EncryptionAlgorithm.Algorithm.Equal(oidPBES2Fixture))

	var params pbes2ParamsFixture
	rest, err := asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &params)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.True(t, params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2Fixture))
	require.True(t, params.EncryptionScheme.Algorithm.Equal(oidAES256CBCFixture))

	var kdf pbkdf2ParamsFixture
	rest, err = asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Len(t, kdf.Salt, 16)
	require.Equal(t, 100_000, kdf.IterationCount)
	require.True(t, kdf.PRF.Algorithm.Equal(oidHMACSHA256Fixture))

	var iv []byte
	rest, err = asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Len(t, iv, 16)
}

func TestUnmarshalPrivateKey_MalformedEncryptedPKCS8ReturnsError(t *testing.T) {
	t.Run("unaligned ciphertext", func(t *testing.T) {
		info := decodeEncryptedPKCS8Info(t, marshalEncryptedPKCS8Block(t).Bytes)
		require.Greater(t, len(info.EncryptedData), 1)
		info.EncryptedData = info.EncryptedData[:len(info.EncryptedData)-1]

		_, err := pkicrypto.UnmarshalPrivateKey(encodeEncryptedPKCS8Info(t, info), "testpass")
		require.Error(t, err)
	})

	t.Run("short IV", func(t *testing.T) {
		info := decodeEncryptedPKCS8Info(t, marshalEncryptedPKCS8Block(t).Bytes)
		var params pbes2ParamsFixture
		_, err := asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &params)
		require.NoError(t, err)
		ivDER, err := asn1.Marshal([]byte{1})
		require.NoError(t, err)
		params.EncryptionScheme.Parameters = asn1.RawValue{FullBytes: ivDER}
		paramsDER, err := asn1.Marshal(params)
		require.NoError(t, err)
		info.EncryptionAlgorithm.Parameters = asn1.RawValue{FullBytes: paramsDER}

		_, err = pkicrypto.UnmarshalPrivateKey(encodeEncryptedPKCS8Info(t, info), "testpass")
		require.Error(t, err)
	})

	t.Run("invalid iteration count", func(t *testing.T) {
		info := decodeEncryptedPKCS8Info(t, marshalEncryptedPKCS8Block(t).Bytes)
		var params pbes2ParamsFixture
		_, err := asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &params)
		require.NoError(t, err)
		var kdf pbkdf2ParamsFixture
		_, err = asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf)
		require.NoError(t, err)
		kdf.IterationCount = -1
		kdfDER, err := asn1.Marshal(kdf)
		require.NoError(t, err)
		params.KeyDerivationFunc.Parameters = asn1.RawValue{FullBytes: kdfDER}
		paramsDER, err := asn1.Marshal(params)
		require.NoError(t, err)
		info.EncryptionAlgorithm.Parameters = asn1.RawValue{FullBytes: paramsDER}

		_, err = pkicrypto.UnmarshalPrivateKey(encodeEncryptedPKCS8Info(t, info), "testpass")
		require.Error(t, err)
	})
}

func TestUnmarshalPrivateKey_OpenSSLEncryptedPKCS8(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/openssl-encrypted-pkcs8.pem")
	require.NoError(t, err)

	key, err := pkicrypto.UnmarshalPrivateKey(pemBytes, "test-pass")
	require.NoError(t, err)
	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok)

	_, err = pkicrypto.UnmarshalPrivateKey(pemBytes, "wrong")
	assert.Error(t, err)
}

func TestUnmarshalPrivateKey_LegacyEncryptedPEMStillWorks(t *testing.T) {
	key, err := pkicrypto.GenKey("rsa", 1024, nil)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", der, []byte("legacy-pass"), x509.PEMCipherAES256) //nolint:staticcheck // compatibility fixture
	require.NoError(t, err)

	recovered, err := pkicrypto.UnmarshalPrivateKey(pem.EncodeToMemory(block), "legacy-pass")
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

func marshalEncryptedPKCS8Block(t *testing.T) *pem.Block {
	t.Helper()
	key, err := pkicrypto.GenKey("rsa", 1024, nil)
	require.NoError(t, err)
	pemBytes, err := pkicrypto.MarshalPrivateKey(key, "testpass")
	require.NoError(t, err)
	block, rest := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Empty(t, rest)
	return block
}

func decodeEncryptedPKCS8Info(t *testing.T, der []byte) encryptedPrivateKeyInfoFixture {
	t.Helper()
	var info encryptedPrivateKeyInfoFixture
	rest, err := asn1.Unmarshal(der, &info)
	require.NoError(t, err)
	require.Empty(t, rest)
	return info
}

func encodeEncryptedPKCS8Info(t *testing.T, info encryptedPrivateKeyInfoFixture) []byte {
	t.Helper()
	der, err := asn1.Marshal(info)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
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
