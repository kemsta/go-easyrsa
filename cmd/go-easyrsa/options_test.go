package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
)

func TestBuildCommonOptions_RequiresNewSubjToken(t *testing.T) {
	opts := defaultCLIOptions()
	opts.newSubject = "/CN=replaced"
	certType := cert.CertTypeClient

	_, err := buildCommonOptions(&opts, pki.Config{}, "client1", commandScopeSign, &certType, map[string]bool{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "newsubj")
}

func TestBuildCommonOptions_AppliesSubCAPathLenForSignReqCA(t *testing.T) {
	opts := defaultCLIOptions()
	opts.subcaLen = 0
	certType := cert.CertTypeCA

	applied, err := buildCommonOptions(&opts, pki.Config{}, "sub1", commandScopeSign, &certType, map[string]bool{})
	require.NoError(t, err)
	require.NotEmpty(t, applied)
}

func TestResolveSANs_AutoSANUsesCN(t *testing.T) {
	opts := defaultCLIOptions()
	opts.autoSAN = true
	opts.reqCN = "vpn.example.test"

	dns, ips, emails, err := resolveSANs(&opts, "ignored")
	require.NoError(t, err)
	require.Equal(t, []string{"vpn.example.test"}, dns)
	require.Empty(t, ips)
	require.Empty(t, emails)
}

func TestResolveSANs_InvalidEntryFails(t *testing.T) {
	opts := defaultCLIOptions()
	opts.sans = []string{"wat"}

	_, _, _, err := resolveSANs(&opts, "name")
	require.Error(t, err)
}

func TestParseCommandOpts_RejectsUnknownToken(t *testing.T) {
	_, err := parseCommandOpts([]string{"wat"}, "nopass")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown command option")
}

func TestSubjectFromCLI_UsesReqCNFromEnv(t *testing.T) {
	t.Setenv("EASYRSA_REQ_CN", "env.example.test")

	opts := defaultCLIOptions()
	subj, has := subjectFromCLI(&opts)
	require.True(t, has)
	require.Equal(t, "env.example.test", subj.CommonName)
}

func TestSubjectFromCLI_UsesReqEmailFlag(t *testing.T) {
	opts := defaultCLIOptions()
	opts.reqEmail = "ops@example.test"

	subj, has := subjectFromCLI(&opts)
	require.True(t, has)
	require.Len(t, subj.ExtraNames, 1)
	require.Equal(t, "ops@example.test", subj.ExtraNames[0].Value)
}

func TestResolveSANs_AutoSANUsesEnvReqCN(t *testing.T) {
	t.Setenv("EASYRSA_REQ_CN", "env.example.test")
	t.Setenv("EASYRSA_AUTO_SAN", "1")

	opts := defaultCLIOptions()
	dns, ips, emails, err := resolveSANs(&opts, "ignored")
	require.NoError(t, err)
	require.Equal(t, []string{"env.example.test"}, dns)
	require.Empty(t, ips)
	require.Empty(t, emails)
}

func TestResolveSANs_ParsesEnvSANEntries(t *testing.T) {
	t.Setenv("EASYRSA_SAN", "DNS:env.example.test,IP:127.0.0.1,EMAIL:ops@example.test")

	opts := defaultCLIOptions()
	dns, ips, emails, err := resolveSANs(&opts, "ignored")
	require.NoError(t, err)
	require.Equal(t, []string{"env.example.test"}, dns)
	require.Len(t, ips, 1)
	require.Equal(t, "127.0.0.1", ips[0].String())
	require.Equal(t, []string{"ops@example.test"}, emails)
}

func TestResolveSANs_AccumulatesEnvAndBothFlagAliases(t *testing.T) {
	t.Setenv("EASYRSA_SAN", "DNS:env.example.test")

	opts := defaultCLIOptions()
	opts.sans = []string{"DNS:flag.example.test"}
	opts.subjectAltNames = []string{"DNS:alias.example.test"}

	dns, ips, emails, err := resolveSANs(&opts, "ignored")
	require.NoError(t, err)
	require.Equal(t, []string{"env.example.test", "flag.example.test", "alias.example.test"}, dns)
	require.Empty(t, ips)
	require.Empty(t, emails)
}

func TestResolveValidity_UsesEnvDates(t *testing.T) {
	t.Setenv("EASYRSA_START_DATE", "20240101000000Z")
	t.Setenv("EASYRSA_END_DATE", "20240102000000Z")

	opts := defaultCLIOptions()
	notBefore, notAfter, err := resolveValidity(&opts)
	require.NoError(t, err)
	require.Equal(t, "2024-01-01T00:00:00Z", notBefore.UTC().Format("2006-01-02T15:04:05Z"))
	require.Equal(t, "2024-01-02T00:00:00Z", notAfter.UTC().Format("2006-01-02T15:04:05Z"))
}

func TestBuildCommonOptions_AppliesEnvNewSubjectWithToken(t *testing.T) {
	t.Setenv("EASYRSA_NEW_SUBJECT", "/CN=replaced/O=Acme")

	opts := defaultCLIOptions()
	certType := cert.CertTypeClient
	applied, err := buildCommonOptions(&opts, pki.Config{}, "client1", commandScopeSign, &certType, map[string]bool{"newsubj": true})
	require.NoError(t, err)
	require.NotEmpty(t, applied)
}

func TestBuildCommonOptions_RejectsUnsupportedResultAffectingEnv(t *testing.T) {
	t.Setenv("EASYRSA_DIGEST", "sha512")

	opts := defaultCLIOptions()
	certType := cert.CertTypeClient
	_, err := buildCommonOptions(&opts, pki.Config{}, "client1", commandScopeBuildFull, &certType, map[string]bool{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "EASYRSA_DIGEST")
}

func TestBuildCommonOptions_AllowsUnsupportedCriticalityEnvWhenExplicitlyFalse(t *testing.T) {
	t.Setenv("EASYRSA_BC_CRIT", "0")

	opts := defaultCLIOptions()
	certType := cert.CertTypeClient
	_, err := buildCommonOptions(&opts, pki.Config{}, "client1", commandScopeBuildFull, &certType, map[string]bool{})
	require.NoError(t, err)
}

func TestBuildCommonOptions_StrictUnsupportedEnvCanBeDisabled(t *testing.T) {
	t.Setenv("EASYRSA_DIGEST", "sha512")
	t.Setenv("GO_EASYRSA_STRICT_ENV_PARITY", "0")

	opts := defaultCLIOptions()
	certType := cert.CertTypeClient
	_, err := buildCommonOptions(&opts, pki.Config{}, "client1", commandScopeBuildFull, &certType, map[string]bool{})
	require.NoError(t, err)
}

func TestStrictEnvParityEnabled_AcceptsAlias(t *testing.T) {
	t.Setenv("STRICT_ENV_PARITY", "0")
	require.False(t, strictEnvParityEnabled())
}
