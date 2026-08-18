package main

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func TestBuildConfig_FlagsOverrideEnv(t *testing.T) {
	t.Setenv("EASYRSA_ALGO", "ec")
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_ORG", "Env Org")
	t.Setenv("EASYRSA_PASSIN", "pass:env-pass")

	opts := defaultCLIOptions()
	opts.algo = "rsa"
	opts.dnMode = "cn_only"
	opts.reqOrg = "Flag Org"
	opts.passIn = "pass:flag-pass"

	cfg, err := buildConfig(&opts)
	require.NoError(t, err)
	require.Equal(t, pki.AlgoRSA, cfg.KeyAlgo)
	require.Equal(t, pki.DNModeCNOnly, cfg.DNMode)
	require.Equal(t, []string{"Flag Org"}, cfg.SubjTemplate.Organization)
	require.Equal(t, "flag-pass", cfg.CAPassphrase)
	require.Equal(t, "flag-pass", cfg.KeyPassphrase)
}

func TestBuildConfig_InvalidCurveFails(t *testing.T) {
	opts := defaultCLIOptions()
	opts.curve = "wat"

	_, err := buildConfig(&opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown curve")
}

func TestDefaultCLIOptions_ReadsEnvBackedPKIAndKeySize(t *testing.T) {
	t.Setenv("EASYRSA_PKI", "/tmp/env-pki")
	t.Setenv("EASYRSA_KEY_SIZE", "4096")

	opts := defaultCLIOptions()
	require.Equal(t, "/tmp/env-pki", opts.pkiDir)
	require.Equal(t, 4096, opts.keySize)
}

func TestDefaultCLIOptions_InvalidNoPassDoesNotDisableEncryption(t *testing.T) {
	t.Setenv("EASYRSA_NO_PASS", "flase")

	opts := defaultCLIOptions()

	require.False(t, opts.noPass)
}

func TestBuildConfig_ExplicitNoPassFalseOverridesEnv(t *testing.T) {
	t.Setenv("EASYRSA_NO_PASS", "true")

	opts := defaultCLIOptions()
	opts.noPass = false
	opts.noPassSet = true
	cfg, err := buildConfig(&opts)

	require.NoError(t, err)
	require.False(t, cfg.NoPass)
}

func TestBuildConfig_ECDSAEnvDefaultsCurveToP384(t *testing.T) {
	t.Setenv("EASYRSA_ALGO", "ec")

	cfg, err := buildConfig(&cliOptions{})
	require.NoError(t, err)
	require.Equal(t, pki.AlgoECDSA, cfg.KeyAlgo)
	require.NotNil(t, cfg.Curve)
	require.Equal(t, elliptic.P384().Params().Name, cfg.Curve.Params().Name)
}

func TestBuildConfig_KeySizeFlagOverridesEnv(t *testing.T) {
	t.Setenv("EASYRSA_KEY_SIZE", "2048")

	opts := defaultCLIOptions()
	opts.keySize = 4096

	cfg, err := buildConfig(&opts)
	require.NoError(t, err)
	require.Equal(t, 4096, cfg.KeySize)
}

func TestBuildConfig_UsesEnvCRLDays(t *testing.T) {
	t.Setenv("EASYRSA_CRL_DAYS", "7")

	cfg, err := buildConfig(&cliOptions{})
	require.NoError(t, err)
	require.Equal(t, 7, cfg.CRLDays)
}

func TestBuildConfig_UsesEnvSubjectTemplateFields(t *testing.T) {
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_COUNTRY", "DE")
	t.Setenv("EASYRSA_REQ_PROVINCE", "Berlin")
	t.Setenv("EASYRSA_REQ_CITY", "Berlin")
	t.Setenv("EASYRSA_REQ_ORG", "Acme Corp")
	t.Setenv("EASYRSA_REQ_OU", "PKI")
	t.Setenv("EASYRSA_REQ_EMAIL", "ops@example.test")

	cfg, err := buildConfig(&cliOptions{})
	require.NoError(t, err)
	require.Equal(t, pki.DNModeOrg, cfg.DNMode)
	require.Equal(t, []string{"DE"}, cfg.SubjTemplate.Country)
	require.Equal(t, []string{"Berlin"}, cfg.SubjTemplate.Province)
	require.Equal(t, []string{"Berlin"}, cfg.SubjTemplate.Locality)
	require.Equal(t, []string{"Acme Corp"}, cfg.SubjTemplate.Organization)
	require.Equal(t, []string{"PKI"}, cfg.SubjTemplate.OrganizationalUnit)
	require.Len(t, cfg.SubjTemplate.ExtraNames, 1)
	require.Equal(t, "ops@example.test", cfg.SubjTemplate.ExtraNames[0].Value)
}

func TestDefaultCLIOptions_ReadsEnvNoPassPassAndSANFlags(t *testing.T) {
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_PASSIN", "pass:secret-in")
	t.Setenv("EASYRSA_PASSOUT", "pass:secret-out")
	t.Setenv("EASYRSA_CP_EXT", "1")
	t.Setenv("EASYRSA_AUTO_SAN", "1")
	t.Setenv("EASYRSA_SAN", "DNS:env.example.test,IP:127.0.0.1")

	opts := defaultCLIOptions()
	require.True(t, opts.noPass)
	require.Equal(t, "pass:secret-in", opts.passIn)
	require.Equal(t, "pass:secret-out", opts.passOut)
	require.True(t, opts.copyExt)
	require.True(t, opts.autoSAN)
	require.Empty(t, opts.sans)
}

func TestDefaultCLIOptions_ReadsEnvDatesAndSigningFlags(t *testing.T) {
	t.Setenv("EASYRSA_START_DATE", "20240101000000Z")
	t.Setenv("EASYRSA_END_DATE", "20250101000000Z")
	t.Setenv("EASYRSA_SUBCA_LEN", "0")
	t.Setenv("EASYRSA_NEW_SUBJECT", "/CN=replaced")

	opts := defaultCLIOptions()
	require.Equal(t, "20240101000000Z", opts.startDate)
	require.Equal(t, "20250101000000Z", opts.endDate)
	require.Equal(t, 0, opts.subcaLen)
	require.Equal(t, "/CN=replaced", opts.newSubject)
}

func TestBuildConfig_UsesEnvValidityDays(t *testing.T) {
	t.Setenv("EASYRSA_CA_EXPIRE", "3651")
	t.Setenv("EASYRSA_CERT_EXPIRE", "30")

	cfg, err := buildConfig(&cliOptions{})
	require.NoError(t, err)
	require.Equal(t, 3651, cfg.CADays)
	require.Equal(t, 30, cfg.DefaultDays)
}

func TestDefaultCLIOptions_ReadsEnvPreserveBatchAndRawCA(t *testing.T) {
	t.Setenv("EASYRSA_PRESERVE_DN", "1")
	t.Setenv("EASYRSA_BATCH", "1")
	t.Setenv("EASYRSA_RAW_CA", "1")
	t.Setenv("EASYRSA_P12_FR_NAME", "custom-name")

	opts := defaultCLIOptions()
	require.True(t, opts.preserveDN)
	require.True(t, opts.batch)
	require.Equal(t, "1", opts.rawCA)
	require.Equal(t, "custom-name", opts.useFN)
}
