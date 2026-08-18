package pki_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func TestLoadConfigFromEnv_OverlaysBase(t *testing.T) {
	base := pki.Config{
		KeyAlgo:          pki.AlgoRSA,
		KeySize:          4096,
		DefaultDays:      30,
		CADays:           365,
		CRLDays:          7,
		PreExpiryDays:    14,
		DNMode:           pki.DNModeCNOnly,
		NoPass:           false,
		CAPassphrase:     "base-ca",
		KeyPassphrase:    "base-key",
		SequentialSerial: false,
	}

	t.Setenv("EASYRSA_ALGO", "ec")
	t.Setenv("EASYRSA_KEY_SIZE", "2048")
	t.Setenv("EASYRSA_CURVE", "secp521r1")
	t.Setenv("EASYRSA_CERT_EXPIRE", "825")
	t.Setenv("EASYRSA_CA_EXPIRE", "3650")
	t.Setenv("EASYRSA_CRL_DAYS", "180")
	t.Setenv("EASYRSA_PRE_EXPIRY_WINDOW", "90")
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_COUNTRY", "DE")
	t.Setenv("EASYRSA_REQ_ORG", "Acme")
	t.Setenv("EASYRSA_REQ_EMAIL", "ops@example.test")
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_PASSIN", "pass:env-secret")
	t.Setenv("EASYRSA_RAND_SN", "no")

	cfg := pki.LoadConfigFromEnv(base)

	assert.Equal(t, pki.AlgoECDSA, cfg.KeyAlgo)
	assert.Equal(t, 2048, cfg.KeySize)
	require.NotNil(t, cfg.Curve)
	assert.Equal(t, elliptic.P521().Params().Name, cfg.Curve.Params().Name)
	assert.Equal(t, 825, cfg.DefaultDays)
	assert.Equal(t, 3650, cfg.CADays)
	assert.Equal(t, 180, cfg.CRLDays)
	assert.Equal(t, 90, cfg.PreExpiryDays)
	assert.Equal(t, pki.DNModeOrg, cfg.DNMode)
	assert.Equal(t, []string{"DE"}, cfg.SubjTemplate.Country)
	assert.Equal(t, []string{"Acme"}, cfg.SubjTemplate.Organization)
	assert.True(t, cfg.NoPass)
	assert.Equal(t, "env-secret", cfg.CAPassphrase)
	assert.Equal(t, "env-secret", cfg.KeyPassphrase)
	assert.True(t, cfg.SequentialSerial)
	require.NotEmpty(t, cfg.SubjTemplate.ExtraNames)
}

func TestLoadConfigFromEnv_InvalidValuesKeepBase(t *testing.T) {
	base := pki.Config{
		KeyAlgo:          pki.AlgoRSA,
		KeySize:          3072,
		Curve:            elliptic.P256(),
		DNMode:           pki.DNModeOrg,
		SequentialSerial: true,
	}

	t.Setenv("EASYRSA_ALGO", "wat")
	t.Setenv("EASYRSA_KEY_SIZE", "not-an-int")
	t.Setenv("EASYRSA_CURVE", "made-up")
	t.Setenv("EASYRSA_DN", "broken")
	t.Setenv("EASYRSA_RAND_SN", "maybe")

	cfg := pki.LoadConfigFromEnv(base)

	assert.Equal(t, base.KeyAlgo, cfg.KeyAlgo)
	assert.Equal(t, base.KeySize, cfg.KeySize)
	require.NotNil(t, cfg.Curve)
	assert.Equal(t, base.Curve.Params().Name, cfg.Curve.Params().Name)
	assert.Equal(t, base.DNMode, cfg.DNMode)
	assert.Equal(t, base.SequentialSerial, cfg.SequentialSerial)
}

func TestLoadConfigFromEnv_InvalidNumericRangesKeepBase(t *testing.T) {
	base := pki.Config{
		KeySize:       3072,
		DefaultDays:   30,
		CADays:        365,
		CRLDays:       7,
		PreExpiryDays: 14,
	}
	t.Setenv("EASYRSA_KEY_SIZE", "0")
	t.Setenv("EASYRSA_CERT_EXPIRE", "-1")
	t.Setenv("EASYRSA_CA_EXPIRE", "0")
	t.Setenv("EASYRSA_CRL_DAYS", "-2")
	t.Setenv("EASYRSA_PRE_EXPIRY_WINDOW", "-1")

	cfg := pki.LoadConfigFromEnv(base)

	assert.Equal(t, base.KeySize, cfg.KeySize)
	assert.Equal(t, base.DefaultDays, cfg.DefaultDays)
	assert.Equal(t, base.CADays, cfg.CADays)
	assert.Equal(t, base.CRLDays, cfg.CRLDays)
	assert.Equal(t, base.PreExpiryDays, cfg.PreExpiryDays)
}

func TestLoadConfigFromEnv_InvalidNoPassKeepsBase(t *testing.T) {
	base := pki.Config{NoPass: false}
	t.Setenv("EASYRSA_NO_PASS", "flase")

	cfg := pki.LoadConfigFromEnv(base)

	assert.False(t, cfg.NoPass)
}

func TestLoadConfigFromEnv_PassphraseIsParsedOnceAndWhitespaceIsPreserved(t *testing.T) {
	t.Setenv("EASYRSA_PASSIN", "pass:pass:secret ")

	cfg := pki.LoadConfigFromEnv(pki.Config{})

	assert.Equal(t, "pass:secret ", cfg.CAPassphrase)
	assert.Equal(t, "pass:secret ", cfg.KeyPassphrase)
}

func TestLoadConfigFromEnv_ECDSAEnvDefaultsCurveToP384(t *testing.T) {
	t.Setenv("EASYRSA_ALGO", "ec")

	cfg := pki.LoadConfigFromEnv(pki.Config{})
	require.NotNil(t, cfg.Curve)
	assert.Equal(t, elliptic.P384().Params().Name, cfg.Curve.Params().Name)
}

func TestLoadConfigFromEnv_EmailAppearsInIssuedSubject(t *testing.T) {
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_ORG", "Acme Corp")
	t.Setenv("EASYRSA_REQ_EMAIL", "pki@example.test")

	cfg := pki.LoadConfigFromEnv(pki.Config{NoPass: true})
	pk := newTestPKI(cfg)

	pair, err := pk.BuildCA(pki.WithNoPass())
	require.NoError(t, err)

	cert, err := pair.Certificate()
	require.NoError(t, err)

	var found bool
	for _, name := range cert.Subject.Names {
		if name.Type.String() == "1.2.840.113549.1.9.1" && name.Value == "pki@example.test" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected emailAddress attribute in subject")
}
