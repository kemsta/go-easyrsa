//go:build e2e

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/kemsta/go-easyrsa/v2/cert"
	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

var testEmailAddressOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func TestMain(m *testing.M) {
	code := m.Run()
	if goEasyRSADir != "" {
		_ = os.RemoveAll(goEasyRSADir)
	}
	os.Exit(code)
}

type binaryRunner struct {
	binary string
	env    []string
	pkiDir string
}

type commandResult struct {
	argv   []string
	stdout string
	stderr string
	err    error
}

func (r commandResult) combinedOutput() string {
	return r.stdout + r.stderr
}

type scenarioStep struct {
	args []string
}

type stateSnapshot struct {
	CA       *pairMeta
	CAName   string
	Index    []indexMeta
	Pairs    []pairMeta
	Requests []requestMeta
	CRL      []crlMeta
}

type indexMeta struct {
	Status  string
	CN      string
	Current bool
}

type pairMeta struct {
	Name          string
	CN            string
	Country       []string
	Province      []string
	Locality      []string
	Organizations []string
	OrgUnits      []string
	SubjectEmails []string
	SubjectSerial string
	Type          string
	IsCA          bool
	HasKey        bool
	DNS           []string
	IPs           []string
	Emails        []string
	NotAfterUnix  int64
	PublicKeyAlgo string
	PublicKeyInfo string
}

type requestMeta struct {
	Name          string
	CN            string
	Country       []string
	Province      []string
	Locality      []string
	Organizations []string
	OrgUnits      []string
	SubjectEmails []string
	SubjectSerial string
	DNS           []string
	IPs           []string
	Emails        []string
	PublicKeyAlgo string
	PublicKeyInfo string
}

type crlMeta struct {
	CN         string
	ReasonCode int
}

type certificateIdentity struct {
	Serial       string
	PublicKeyDER []byte
}

type p12Meta struct {
	KeyBlocks             int
	CertCNs               []string
	KeyMatchesCertificate bool
}

type p7CertificateMeta struct {
	CN            string
	IsCA          bool
	PublicKeyAlgo string
	PublicKeyInfo string
}

type p7Meta struct {
	Certificates []p7CertificateMeta
}

type pemKeyMeta struct {
	Type          string
	Encrypted     bool
	PublicKeyAlgo string
	PublicKeyInfo string
	PublicKeyDER  []byte
}

func TestE2E_BuildClientFullParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_BuildServerFullOrgModeParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_DN=org",
		"EASYRSA_REQ_ORG=Acme Corp",
		"EASYRSA_REQ_EMAIL=pki@example.test",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"--san=DNS:vpn.example.test", "--san=IP:127.0.0.1", "build-server-full", "vpn"}},
	})
}

func TestE2E_BuildServerClientFullParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-serverClient-full", "node1"}},
	})
}

func TestE2E_GenReqSignReqParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"--san=DNS:vpn.example.test", "--san=IP:127.0.0.1", "gen-req", "server1"}},
		{args: []string{"--copy-ext", "sign-req", "server", "server1"}},
	})
}

func TestE2E_ImportReqParity(t *testing.T) {
	csrPath := writeExternalCSR(t, "external1")
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"import-req", csrPath, "external1"}},
		{args: []string{"sign-req", "client", "external1"}},
	})
}

func TestE2E_RenewParity(t *testing.T) {
	runScenarioAndCompareWithOptions(t, []string{"EASYRSA_NO_PASS=1"}, nil, stateComparisonOptions{normalizeSupersededRenewal: true}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
		{args: []string{"renew", "alice"}},
	})
}

func TestE2E_RenewCAParity(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, []string{"EASYRSA_NO_PASS=1"}, nil)
	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		out, err := runner.run("init-pki")
		require.NoError(t, err, out)
		out, err = runner.run("build-ca")
		require.NoError(t, err, out)
	}
	goBefore := caIdentity(t, goDir)
	easyBefore := caIdentity(t, easyDir)
	goRunner.env = append(goRunner.env, "EASYRSA_SAN=DNS:renewed-ca.example.test")
	easyRunner.env = append(easyRunner.env, "EASYRSA_SAN=DNS:renewed-ca.example.test")

	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		out, err := runner.run("renew-ca")
		require.NoError(t, err, out)
	}
	goAfter := caIdentity(t, goDir)
	easyAfter := caIdentity(t, easyDir)
	require.NotEqual(t, goBefore.Serial, goAfter.Serial)
	require.NotEqual(t, easyBefore.Serial, easyAfter.Serial)
	require.Equal(t, goBefore.PublicKeyDER, goAfter.PublicKeyDER)
	require.Equal(t, easyBefore.PublicKeyDER, easyAfter.PublicKeyDER)
	compareStates(t, loadState(t, easyDir), loadState(t, goDir), stateComparisonOptions{})
}

func TestE2E_ExpireAndUpdateDBParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"--startdate=20200101000000Z", "--enddate=20200102000000Z", "build-client-full", "old1"}},
		{args: []string{"update-db"}},
	})
}

func TestE2E_ExpireCommandParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
		{args: []string{"expire", "alice"}},
	})
}

func TestE2E_RevokeExpiredCommandParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"--startdate=20200101000000Z", "--enddate=20200102000000Z", "build-client-full", "old1"}},
		{args: []string{"expire", "old1"}},
		{args: []string{"revoke-expired", "old1"}},
		{args: []string{"gen-crl"}},
	})
}

func TestE2E_RevokeCRLParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, nil, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
		{args: []string{"revoke-issued", "alice"}},
		{args: []string{"gen-crl"}},
	})
}

func TestE2E_InspectionAndRevokeAliasCommands(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, []string{"EASYRSA_NO_PASS=1"}, nil)
	for _, step := range []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
		{args: []string{"gen-crl"}},
	} {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}

	for _, check := range []struct {
		args   []string
		marker string
	}{
		{args: []string{"show-ca"}, marker: "easy-rsa ca"},
		{args: []string{"show-cert", "alice"}, marker: "alice"},
		{args: []string{"show-crl"}, marker: "revoked"},
	} {
		out, err := easyRunner.run(check.args...)
		require.NoError(t, err, "easyrsa %v\n%s", check.args, out)
		require.Contains(t, strings.ToLower(out), check.marker)
		out, err = goRunner.run(check.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", check.args, out)
		require.Contains(t, strings.ToLower(out), check.marker)
	}

	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		out, err := runner.run("revoke", "alice")
		require.NoError(t, err, out)
		out, err = runner.run("show-revoke", "alice")
		require.NoError(t, err, out)
		require.Contains(t, strings.ToLower(out), "alice")
		out, err = runner.run("gen-crl")
		require.NoError(t, err, out)
	}
	compareStates(t, loadState(t, easyDir), loadState(t, goDir), stateComparisonOptions{})
}

func TestE2E_CrossImplementationContinuation(t *testing.T) {
	t.Run("Go PKI continued by Easy-RSA", func(t *testing.T) {
		dir := t.TempDir()
		goRunner, easyRunner := runnersForSharedPKI(t, dir)
		for _, step := range []struct {
			runner binaryRunner
			args   []string
		}{
			{runner: goRunner, args: []string{"init-pki"}},
			{runner: goRunner, args: []string{"build-ca", "nopass"}},
			{runner: goRunner, args: []string{"build-client-full", "alice", "nopass"}},
			{runner: easyRunner, args: []string{"verify-cert", "alice"}},
			{runner: easyRunner, args: []string{"build-client-full", "bob", "nopass"}},
			{runner: goRunner, args: []string{"verify-cert", "bob"}},
			{runner: goRunner, args: []string{"gen-crl"}},
			{runner: easyRunner, args: []string{"show-crl"}},
		} {
			out, err := step.runner.run(step.args...)
			require.NoError(t, err, "%v\n%s", step.args, out)
		}
	})

	t.Run("Easy-RSA PKI continued by Go", func(t *testing.T) {
		dir := t.TempDir()
		goRunner, easyRunner := runnersForSharedPKI(t, dir)
		for _, step := range []struct {
			runner binaryRunner
			args   []string
		}{
			{runner: easyRunner, args: []string{"init-pki"}},
			{runner: easyRunner, args: []string{"build-ca", "nopass"}},
			{runner: easyRunner, args: []string{"build-client-full", "alice", "nopass"}},
			{runner: goRunner, args: []string{"verify-cert", "alice"}},
			{runner: goRunner, args: []string{"build-client-full", "bob", "nopass"}},
			{runner: easyRunner, args: []string{"verify-cert", "bob"}},
		} {
			out, err := step.runner.run(step.args...)
			require.NoError(t, err, "%v\n%s", step.args, out)
		}
	})
}

func TestE2E_SetPassParity(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, nil, nil)
	setup := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca", "nopass"}},
		{args: []string{"build-client-full", "alice", "nopass"}},
	}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}

	out, err := easyRunner.run("--passout=pass:newsecret", "set-pass", "alice")
	require.NoError(t, err, out)
	out, err = goRunner.run("--passout=pass:newsecret", "set-pass", "alice")
	require.NoError(t, err, out)

	compareStates(t, loadState(t, easyDir), loadState(t, goDir), stateComparisonOptions{})
	assertKeyPassphrase(t, easyDir, "alice", "newsecret")
	assertKeyPassphrase(t, goDir, "alice", "newsecret")
}

func TestE2E_ExportP12Parity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca", "nopass"}},
		{args: []string{"build-client-full", "alice", "nopass"}},
	}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}

	easyOut, err := easyRunner.run("--passout=pass:exportpass", "export-p12", "alice")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("--passout=pass:exportpass", "export-p12", "alice")
	require.NoError(t, err, goOut)

	easyData := easyRunner.readArtifact(t, "private", "alice.p12")
	goData := goRunner.readArtifact(t, "private", "alice.p12")
	easyMeta := parseP12Meta(t, easyData, "exportpass")
	goMeta := parseP12Meta(t, goData, "exportpass")
	require.True(t, easyMeta.KeyMatchesCertificate)
	require.True(t, goMeta.KeyMatchesCertificate)
	require.Equal(t, easyMeta, goMeta)
}

func TestE2E_ExportP12LegacyParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{{args: []string{"init-pki"}}, {args: []string{"build-ca", "nopass"}}, {args: []string{"build-client-full", "alice", "nopass"}}}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("--passout=pass:exportpass", "export-p12", "alice", "legacy")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("--passout=pass:exportpass", "export-p12", "alice", "legacy")
	require.NoError(t, err, goOut)
	easyData := easyRunner.readArtifact(t, "private", "alice.p12")
	goData := goRunner.readArtifact(t, "private", "alice.p12")
	easyMeta := parseP12Meta(t, easyData, "exportpass")
	goMeta := parseP12Meta(t, goData, "exportpass")
	require.True(t, easyMeta.KeyMatchesCertificate)
	require.True(t, goMeta.KeyMatchesCertificate)
	require.True(t, hasLegacyPKCS12Profile(t, easyData, "exportpass"))
	require.True(t, hasLegacyPKCS12Profile(t, goData, "exportpass"))
	require.Equal(t, easyMeta, goMeta)
}

func TestE2E_ExportP12NoCAParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{{args: []string{"init-pki"}}, {args: []string{"build-ca", "nopass"}}, {args: []string{"build-client-full", "alice", "nopass"}}}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("--passout=pass:exportpass", "export-p12", "alice", "noca")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("--passout=pass:exportpass", "export-p12", "alice", "noca")
	require.NoError(t, err, goOut)
	easyData := easyRunner.readArtifact(t, "private", "alice.p12")
	goData := goRunner.readArtifact(t, "private", "alice.p12")
	easyMeta := parseP12Meta(t, easyData, "exportpass")
	goMeta := parseP12Meta(t, goData, "exportpass")
	require.True(t, easyMeta.KeyMatchesCertificate)
	require.True(t, goMeta.KeyMatchesCertificate)
	require.Equal(t, easyMeta, goMeta)
}

func TestE2E_ExportP12NoKeyParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{{args: []string{"init-pki"}}, {args: []string{"build-ca", "nopass"}}, {args: []string{"build-client-full", "alice", "nopass"}}}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("--passout=pass:exportpass", "export-p12", "alice", "nokey")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("--passout=pass:exportpass", "export-p12", "alice", "nokey")
	require.NoError(t, err, goOut)
	easyData := easyRunner.readArtifact(t, "private", "alice.p12")
	goData := goRunner.readArtifact(t, "private", "alice.p12")
	easyMeta := parseP12Meta(t, easyData, "exportpass")
	goMeta := parseP12Meta(t, goData, "exportpass")
	require.Zero(t, easyMeta.KeyBlocks)
	require.Zero(t, goMeta.KeyBlocks)
	require.Equal(t, easyMeta, goMeta)
}

func TestE2E_EnvDrivenConfigParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_ALGO=ec",
		"EASYRSA_CURVE=secp384r1",
		"EASYRSA_DN=org",
		"EASYRSA_REQ_ORG=Acme Corp",
		"EASYRSA_REQ_EMAIL=pki@example.test",
		"EASYRSA_AUTO_SAN=1",
		"EASYRSA_CERT_EXPIRE=30",
		"EASYRSA_CA_EXPIRE=3651",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-server-full", "vpn"}},
	})
}

func TestE2E_EnvAlgoCurveParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_ALGO=ec",
		"EASYRSA_CURVE=secp521r1",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_EnvKeySizeParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_KEY_SIZE=4096",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_EnvKeySizeAffectsGenDHParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, []string{
		"EASYRSA_KEY_SIZE=512",
	})
	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		out, err := runner.run("init-pki")
		require.NoError(t, err, out)
	}
	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		out, err := runner.run("gen-dh")
		require.NoError(t, err, out)
		data := runner.readArtifact(t, "dh.pem")
		require.Equal(t, 512, parseDHParameterBits(t, data))
		assertDHParametersValid(t, data)
	}
}

func TestE2E_EnvSANParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_SAN=DNS:env.example.test,IP:127.0.0.1",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-server-full", "vpn"}},
	})
}

func TestE2E_EnvDNCNOnlyParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_DN=cn_only",
		"EASYRSA_REQ_ORG=Acme Corp",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_EnvReqCNAndAutoSANParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_REQ_CN=env.example.test",
		"EASYRSA_AUTO_SAN=1",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-server-full", "vpn"}},
	})
}

func TestE2E_EnvReqSubjectTemplateParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_DN=org",
		"EASYRSA_REQ_COUNTRY=DE",
		"EASYRSA_REQ_PROVINCE=Berlin",
		"EASYRSA_REQ_CITY=Berlin",
		"EASYRSA_REQ_ORG=Acme Corp",
		"EASYRSA_REQ_OU=PKI",
		"EASYRSA_REQ_EMAIL=ops@example.test",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_EnvReqSerialParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_REQ_SERIAL=SER-42",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_EnvNoPassParity(t *testing.T) {
	baseEnv := []string{
		"EASYRSA_BATCH=1",
		"EASYRSA_RAND_SN=no",
	}
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, baseEnv, []string{
		"EASYRSA_NO_PASS=1",
	})
	steps := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	}
	for _, step := range steps {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	compareStates(t, loadState(t, easyDir), loadState(t, goDir), stateComparisonOptions{})
	assertPlaintextKey(t, easyDir, "alice")
	assertPlaintextKey(t, goDir, "alice")
}

func TestE2E_EnvCopyExtParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_CP_EXT=1",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"--san=DNS:csr.example.test", "gen-req", "srv1"}},
		{args: []string{"sign-req", "server", "srv1"}},
	})
}

func TestE2E_EnvPassInPassOutExportP1Parity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, []string{
		"EASYRSA_BATCH=1",
		"EASYRSA_RAND_SN=no",
	}, []string{
		"EASYRSA_PASSOUT=pass:secret123",
		"EASYRSA_PASSIN=pass:secret123",
	})
	steps := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	}
	for _, step := range steps {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("export-p1", "alice")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("export-p1", "alice")
	require.NoError(t, err, goOut)
	easyData := easyRunner.readArtifact(t, "private", "alice.p1")
	goData := goRunner.readArtifact(t, "private", "alice.p1")
	assertPEMKeyParity(t, easyRunner, goRunner, "alice", easyData, goData, "secret123")
}

func TestE2E_EnvCAAndCertExpireParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_CA_EXPIRE=3651",
		"EASYRSA_CERT_EXPIRE=30",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_EnvStartDateEndDateParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_START_DATE=20240101000000Z",
		"EASYRSA_END_DATE=20240102000000Z",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	})
}

func TestE2E_EnvSubcaLenParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_SUBCA_LEN=0",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"gen-req", "sub1"}},
		{args: []string{"sign-req", "ca", "sub1"}},
	})
}

func TestE2E_EnvNewSubjectParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_NEW_SUBJECT=/CN=replaced/O=Acme",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"gen-req", "client1"}},
		{args: []string{"sign-req", "client", "client1", "newsubj"}},
	})
}

func TestE2E_EnvPreserveDNParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_PRESERVE_DN=1",
		"EASYRSA_DN=org",
		"EASYRSA_REQ_ORG=Request Org",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"gen-req", "client1"}},
		{args: []string{"sign-req", "client", "client1"}},
	})
}

func TestE2E_EnvBatchVerifyCertParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, []string{
		"EASYRSA_BATCH=1",
		"EASYRSA_NO_PASS=1",
		"EASYRSA_RAND_SN=no",
	}, nil)
	steps := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
	}
	for _, step := range steps {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("verify-cert", "alice")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("verify-cert", "alice")
	require.NoError(t, err, goOut)
}

func TestE2E_InvalidSANFailureParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{{args: []string{"init-pki"}}, {args: []string{"build-ca", "nopass"}}}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, easyErr := easyRunner.run("--san=wat", "build-server-full", "vpn")
	goOut, goErr := goRunner.run("--san=wat", "build-server-full", "vpn")
	require.Error(t, easyErr, easyOut)
	require.Error(t, goErr, goOut)
}

func TestE2E_EnvPassInPassOutParity(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, []string{
		"EASYRSA_BATCH=1",
		"EASYRSA_RAND_SN=no",
	}, []string{
		"EASYRSA_PASSOUT=pass:secret123",
		"EASYRSA_PASSIN=pass:secret123",
	})
	steps := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
		{args: []string{"renew", "alice"}},
		{args: []string{"gen-crl"}},
	}
	for _, step := range steps {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	assertKeyPassphrase(t, easyDir, "alice", "secret123")
	assertKeyPassphrase(t, goDir, "alice", "secret123")
	compareStates(t, loadState(t, easyDir), loadState(t, goDir), stateComparisonOptions{normalizeSupersededRenewal: true})
}

func TestE2E_EnvCRLDaysParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, []string{
		"EASYRSA_CRL_DAYS=7",
	})
	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		out, err := runner.run("init-pki")
		require.NoError(t, err, out)
		out, err = runner.run("build-ca", "nopass")
		require.NoError(t, err, out)
		out, err = runner.run("gen-crl")
		require.NoError(t, err, out)
		crl := parseCRL(t, runner.readArtifact(t, "crl.pem"))
		require.WithinDuration(t, crl.ThisUpdate.Add(7*24*time.Hour), crl.NextUpdate, 2*time.Minute)
	}
}

func TestE2E_EnvPreExpiryWindowAffectsShowExpire(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, []string{
		"EASYRSA_CERT_EXPIRE=5",
		"EASYRSA_PRE_EXPIRY_WINDOW=10",
	})
	setup := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca", "nopass"}},
		{args: []string{"build-client-full", "soon", "nopass"}},
	}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("show-expire")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("show-expire")
	require.NoError(t, err, goOut)
	require.Contains(t, strings.ToLower(easyOut), "soon")
	require.Contains(t, strings.ToLower(goOut), "soon")
}

func TestE2E_FlagsOverrideEnvParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_ALGO=rsa",
		"EASYRSA_KEY_SIZE=2048",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"--algo=ec", "--curve=prime256v1", "build-ca"}},
		{args: []string{"--algo=ec", "--curve=prime256v1", "build-client-full", "alice"}},
	})
}

func TestE2E_SANFlagOverridesEnvParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_SAN=DNS:env.example.test",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"--san=DNS:flag.example.test", "build-server-full", "vpn"}},
	})
}

func TestE2E_DaysFlagOverridesEnvCertExpireParity(t *testing.T) {
	runScenarioAndCompare(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_CERT_EXPIRE=30",
	}, []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"--days=5", "build-client-full", "alice"}},
	})
}

func TestE2E_SequentialSerialParity(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, []string{"EASYRSA_NO_PASS=1"}, nil)
	for _, step := range []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
		{args: []string{"build-client-full", "bob"}},
	} {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, out)
	}
	assertSequentialSerials(t, easyDir)
	assertSequentialSerials(t, goDir)
}

func TestE2E_EnvRandSNParity(t *testing.T) {
	baseEnv := []string{
		"EASYRSA_BATCH=1",
		"EASYRSA_NO_PASS=1",
	}
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, baseEnv, []string{
		"EASYRSA_RAND_SN=yes",
	})
	steps := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca"}},
		{args: []string{"build-client-full", "alice"}},
		{args: []string{"build-client-full", "bob"}},
	}
	for _, step := range steps {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	assertNonSequentialSerials(t, easyDir)
	assertNonSequentialSerials(t, goDir)
}

func TestE2E_VerifyCertRevokedFailureParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca", "nopass"}},
		{args: []string{"build-client-full", "alice", "nopass"}},
		{args: []string{"revoke-issued", "alice"}},
		{args: []string{"gen-crl"}},
	}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, easyErr := easyRunner.run("verify-cert", "alice", "batch")
	goOut, goErr := goRunner.run("verify-cert", "alice", "batch")
	require.Error(t, easyErr, easyOut)
	require.Error(t, goErr, goOut)
}

func TestE2E_ExportP7Parity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{
		{args: []string{"init-pki"}},
		{args: []string{"build-ca", "nopass"}},
		{args: []string{"build-client-full", "alice", "nopass"}},
	}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}

	easyOut, err := easyRunner.run("export-p7", "alice")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("export-p7", "alice")
	require.NoError(t, err, goOut)

	easyData := easyRunner.readArtifact(t, "issued", "alice.p7b")
	goData := goRunner.readArtifact(t, "issued", "alice.p7b")
	easyMeta := parseP7Meta(t, easyData)
	goMeta := parseP7Meta(t, goData)
	require.Len(t, easyMeta.Certificates, 2)
	require.Len(t, goMeta.Certificates, 2)
	require.Equal(t, easyMeta, goMeta)
}

func TestE2E_ExportP7NoCAParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{{args: []string{"init-pki"}}, {args: []string{"build-ca", "nopass"}}, {args: []string{"build-client-full", "alice", "nopass"}}}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("export-p7", "alice", "noca")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("export-p7", "alice", "noca")
	require.NoError(t, err, goOut)
	easyData := easyRunner.readArtifact(t, "issued", "alice.p7b")
	goData := goRunner.readArtifact(t, "issued", "alice.p7b")
	easyMeta := parseP7Meta(t, easyData)
	goMeta := parseP7Meta(t, goData)
	require.Len(t, easyMeta.Certificates, 1)
	require.Len(t, goMeta.Certificates, 1)
	require.False(t, easyMeta.Certificates[0].IsCA)
	require.False(t, goMeta.Certificates[0].IsCA)
	require.Equal(t, easyMeta, goMeta)
}

func TestE2E_ExportP8Parity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{{args: []string{"init-pki"}}, {args: []string{"build-ca", "nopass"}}, {args: []string{"build-client-full", "alice", "nopass"}}}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("--passout=pass:exportpass", "export-p8", "alice")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("--passout=pass:exportpass", "export-p8", "alice")
	require.NoError(t, err, goOut)
	easyData := easyRunner.readArtifact(t, "private", "alice.p8")
	goData := goRunner.readArtifact(t, "private", "alice.p8")
	assertPEMKeyParity(t, easyRunner, goRunner, "alice", easyData, goData, "exportpass")
}

func TestE2E_ExportP1Parity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	setup := []scenarioStep{{args: []string{"init-pki"}}, {args: []string{"build-ca", "nopass"}}, {args: []string{"build-client-full", "alice", "nopass"}}}
	for _, step := range setup {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)
		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}
	easyOut, err := easyRunner.run("--passout=pass:exportpass", "export-p1", "alice")
	require.NoError(t, err, easyOut)
	goOut, err := goRunner.run("--passout=pass:exportpass", "export-p1", "alice")
	require.NoError(t, err, goOut)
	easyData := easyRunner.readArtifact(t, "private", "alice.p1")
	goData := goRunner.readArtifact(t, "private", "alice.p1")
	assertPEMKeyParity(t, easyRunner, goRunner, "alice", easyData, goData, "exportpass")
}

type stateComparisonOptions struct {
	normalizeSupersededRenewal bool
}

func runScenarioAndCompare(t *testing.T, baseEnv []string, extraEnv []string, steps []scenarioStep) {
	t.Helper()
	runScenarioAndCompareWithOptions(t, baseEnv, extraEnv, stateComparisonOptions{}, steps)
}

func runScenarioAndCompareWithOptions(t *testing.T, baseEnv []string, extraEnv []string, options stateComparisonOptions, steps []scenarioStep) {
	t.Helper()
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, baseEnv, extraEnv)

	for _, step := range steps {
		out, err := easyRunner.run(step.args...)
		require.NoError(t, err, "easyrsa %v\n%s", step.args, out)

		out, err = goRunner.run(step.args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", step.args, out)
	}

	compareStates(t, loadState(t, easyDir), loadState(t, goDir), options)
}

func compareStates(t *testing.T, expected, actual stateSnapshot, options stateComparisonOptions) {
	t.Helper()
	expected = cloneStateSnapshot(expected)
	actual = cloneStateSnapshot(actual)
	if options.normalizeSupersededRenewal {
		normalizeRenewedIndexStatus(expected.Index)
		normalizeRenewedIndexStatus(actual.Index)
	}
	require.NotNil(t, expected.CA)
	require.NotNil(t, actual.CA)
	require.WithinDuration(t, time.Unix(expected.CA.NotAfterUnix, 0), time.Unix(actual.CA.NotAfterUnix, 0), 2*time.Minute)
	expected.CA.NotAfterUnix = 0
	actual.CA.NotAfterUnix = 0
	require.Len(t, actual.Pairs, len(expected.Pairs))
	for i := range expected.Pairs {
		require.Equal(t, expected.Pairs[i].Name, actual.Pairs[i].Name)
		require.Equal(t, expected.Pairs[i].Type, actual.Pairs[i].Type)
		require.WithinDuration(t, time.Unix(expected.Pairs[i].NotAfterUnix, 0), time.Unix(actual.Pairs[i].NotAfterUnix, 0), 2*time.Minute)
		expected.Pairs[i].NotAfterUnix = 0
		actual.Pairs[i].NotAfterUnix = 0
	}
	require.Equal(t, expected, actual)
}

func cloneStateSnapshot(state stateSnapshot) stateSnapshot {
	state.Index = append([]indexMeta(nil), state.Index...)
	state.Pairs = append([]pairMeta(nil), state.Pairs...)
	state.Requests = append([]requestMeta(nil), state.Requests...)
	state.CRL = append([]crlMeta(nil), state.CRL...)
	if state.CA != nil {
		ca := *state.CA
		state.CA = &ca
	}
	return state
}

func runnersForSharedPKI(t *testing.T, dir string) (binaryRunner, binaryRunner) {
	t.Helper()
	repoRoot := findRepoRoot(t)
	env := []string{
		"EASYRSA_BATCH=1",
		"EASYRSA_RAND_SN=no",
		"EASYRSA_PKI=" + dir,
	}
	return binaryRunner{binary: buildGoEasyRSABinary(t), env: env, pkiDir: dir},
		binaryRunner{binary: findEasyRSABinary(t, repoRoot), env: env, pkiDir: dir}
}

func newParityRunners(t *testing.T, baseEnv []string, extraEnv []string) (binaryRunner, binaryRunner, string, string) {
	t.Helper()
	repoRoot := findRepoRoot(t)
	goBinary := buildGoEasyRSABinary(t)
	easyBinary := findEasyRSABinary(t, repoRoot)

	goDir := t.TempDir()
	easyDir := t.TempDir()
	commonEnv := []string{
		"EASYRSA_BATCH=1",
		"EASYRSA_RAND_SN=no",
	}
	commonEnv = append(commonEnv, baseEnv...)
	commonEnv = append(commonEnv, extraEnv...)
	goRunner := binaryRunner{binary: goBinary, env: append(append([]string(nil), commonEnv...), "EASYRSA_PKI="+goDir), pkiDir: goDir}
	easyRunner := binaryRunner{binary: easyBinary, env: append(append([]string(nil), commonEnv...), "EASYRSA_PKI="+easyDir), pkiDir: easyDir}
	return goRunner, easyRunner, goDir, easyDir
}

func (r binaryRunner) run(args ...string) (string, error) {
	result := r.runCommand(args...)
	return result.combinedOutput(), result.err
}

func (r binaryRunner) readArtifact(t *testing.T, path ...string) []byte {
	t.Helper()
	parts := append([]string{r.pkiDir}, path...)
	data, err := os.ReadFile(filepath.Join(parts...))
	require.NoError(t, err)
	return data
}

func (r binaryRunner) runCommand(args ...string) commandResult {
	argv := append([]string(nil), args...)
	if err := validateCanonicalUpstreamArgs(argv); err != nil {
		return commandResult{argv: argv, err: err}
	}
	cmd := exec.Command(r.binary, argv...)
	cmd.Env = sanitizedCommandEnv(r.env)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return commandResult{argv: argv, stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func sanitizedCommandEnv(overrides []string) []string {
	env := make([]string, 0, len(os.Environ())+len(overrides))
	positions := make(map[string]int)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if upper == "EASYRSA" || strings.HasPrefix(upper, "EASYRSA_") || strings.HasPrefix(upper, "GO_EASYRSA_") || upper == "STRICT_ENV_PARITY" {
			continue
		}
		positions[upper] = len(env)
		env = append(env, entry)
	}
	for _, entry := range overrides {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if position, ok := positions[upper]; ok {
			env[position] = entry
			continue
		}
		positions[upper] = len(env)
		env = append(env, entry)
	}
	return env
}

func validateCanonicalUpstreamArgs(args []string) error {
	valueOptions := map[string]bool{
		"--algo": true, "--curve": true, "--days": true, "--dn-mode": true,
		"--enddate": true, "--keysize": true, "--new-subject": true,
		"--passin": true, "--passout": true, "--pki-dir": true, "--req-c": true,
		"--req-city": true, "--req-cn": true, "--req-email": true,
		"--req-org": true, "--req-ou": true, "--req-serial": true,
		"--req-st": true, "--san": true, "--startdate": true,
		"--subject-alt-name": true, "--subca-len": true, "--usefn": true,
	}
	for _, arg := range args {
		if valueOptions[arg] {
			return fmt.Errorf("E2E scenario must use canonical upstream syntax %s=<value>", arg)
		}
	}
	return nil
}

var (
	goEasyRSAOnce   sync.Once
	goEasyRSADir    string
	goEasyRSABinary string
	goEasyRSAErr    error
	goEasyRSAOutput []byte
)

func buildGoEasyRSABinary(t *testing.T) string {
	t.Helper()
	goEasyRSAOnce.Do(func() {
		goEasyRSADir, goEasyRSAErr = os.MkdirTemp("", "go-easyrsa-e2e-")
		if goEasyRSAErr != nil {
			return
		}
		goEasyRSABinary = filepath.Join(goEasyRSADir, "go-easyrsa")
		if runtime.GOOS == "windows" {
			goEasyRSABinary += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", goEasyRSABinary, ".")
		cmd.Dir = "."
		goEasyRSAOutput, goEasyRSAErr = cmd.CombinedOutput()
	})
	require.NoErrorf(t, goEasyRSAErr, "go build failed: %s", goEasyRSAOutput)
	return goEasyRSABinary
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func findEasyRSABinary(t *testing.T, repoRoot string) string {
	t.Helper()
	if override := os.Getenv("EASYRSA_BIN"); override != "" {
		_, err := os.Stat(override)
		require.NoErrorf(t, err, "EASYRSA_BIN points to missing binary: %s", override)
		return override
	}
	binary := filepath.Join(repoRoot, "subprojects", "easy-rsa", "easyrsa3", "easyrsa")
	_, err := os.Stat(binary)
	require.NoErrorf(t, err, "easy-rsa binary not found at %s", binary)
	return binary
}

func loadState(t *testing.T, dir string) stateSnapshot {
	t.Helper()
	pk, err := pki.NewWithFS(dir, pki.Config{NoPass: true, SequentialSerial: true})
	require.NoError(t, err)
	snapshot, err := pk.ExportSnapshot()
	require.NoError(t, err)

	state := stateSnapshot{CAName: snapshot.CAName}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	caCertificate := parseCertificatePEM(t, caPEM)
	caPair := &cert.Pair{Name: snapshot.CAName, CertPEM: caPEM}
	if keyPEM, err := os.ReadFile(filepath.Join(dir, "private", snapshot.CAName+".key")); err == nil {
		caPair.KeyPEM = keyPEM
	} else {
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	caMeta, err := normalizePair(caPair)
	require.NoError(t, err)
	state.CA = &caMeta

	issued, err := filepath.Glob(filepath.Join(dir, "issued", "*.crt"))
	require.NoError(t, err)
	currentSerials := make(map[string]bool)
	for _, certPath := range issued {
		certificate := parseCertificatePEM(t, mustReadFile(t, certPath))
		currentSerials[storage.HexSerial(certificate.SerialNumber)] = true
	}

	caSerials := rootCASerials(t, dir)
	statusBySerial := make(map[string]string)
	nameBySerial := make(map[string]string)
	for _, entry := range snapshot.Index {
		serial := storage.HexSerial(entry.Serial)
		statusBySerial[serial] = string(entry.Status)
		nameBySerial[serial] = entry.Subject.CommonName
		if caSerials[serial] {
			continue
		}
		state.Index = append(state.Index, indexMeta{
			Status:  string(entry.Status),
			CN:      entry.Subject.CommonName,
			Current: currentSerials[serial],
		})
	}
	sort.Slice(state.Index, func(i, j int) bool {
		if state.Index[i].CN != state.Index[j].CN {
			return state.Index[i].CN < state.Index[j].CN
		}
		if state.Index[i].Current != state.Index[j].Current {
			return !state.Index[i].Current
		}
		return state.Index[i].Status < state.Index[j].Status
	})

	for _, certPath := range issued {
		name := strings.TrimSuffix(filepath.Base(certPath), filepath.Ext(certPath))
		certPEM := mustReadFile(t, certPath)
		certificate := parseCertificatePEM(t, certPEM)
		if statusBySerial[storage.HexSerial(certificate.SerialNumber)] == string(storage.StatusRevoked) {
			continue
		}
		pair := &cert.Pair{Name: name, CertPEM: certPEM}
		keyPEM, err := os.ReadFile(filepath.Join(dir, "private", name+".key"))
		if err == nil {
			pair.KeyPEM = keyPEM
		} else {
			require.ErrorIs(t, err, os.ErrNotExist)
		}
		meta, err := normalizePair(pair)
		require.NoError(t, err)
		state.Pairs = append(state.Pairs, meta)
	}
	sort.Slice(state.Pairs, func(i, j int) bool {
		if state.Pairs[i].Name != state.Pairs[j].Name {
			return state.Pairs[i].Name < state.Pairs[j].Name
		}
		return state.Pairs[i].Type < state.Pairs[j].Type
	})

	requests, err := filepath.Glob(filepath.Join(dir, "reqs", "*.req"))
	require.NoError(t, err)
	for _, requestPath := range requests {
		state.Requests = append(state.Requests, normalizeRequest(t, requestPath))
	}
	sort.Slice(state.Requests, func(i, j int) bool { return state.Requests[i].Name < state.Requests[j].Name })

	if crlPEM, err := os.ReadFile(filepath.Join(dir, "crl.pem")); err == nil {
		crl := parseCRL(t, crlPEM)
		require.NoError(t, crl.CheckSignatureFrom(caCertificate))
		for _, revoked := range crl.RevokedCertificateEntries {
			serial := storage.HexSerial(revoked.SerialNumber)
			name := nameBySerial[serial]
			if name == "" {
				name = "serial:" + serial
			}
			state.CRL = append(state.CRL, crlMeta{CN: name, ReasonCode: revoked.ReasonCode})
		}
		sort.Slice(state.CRL, func(i, j int) bool {
			if state.CRL[i].CN != state.CRL[j].CN {
				return state.CRL[i].CN < state.CRL[j].CN
			}
			return state.CRL[i].ReasonCode < state.CRL[j].ReasonCode
		})
	} else {
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	return state
}

func normalizeRenewedIndexStatus(index []indexMeta) {
	for i := range index {
		if !index[i].Current && index[i].Status == string(storage.StatusExpired) {
			index[i].Status = string(storage.StatusValid)
		}
	}
}

func rootCASerials(t *testing.T, dir string) map[string]bool {
	t.Helper()
	paths := []string{filepath.Join(dir, "ca.crt")}
	serialPaths, err := filepath.Glob(filepath.Join(dir, "certs_by_serial", "*.pem"))
	require.NoError(t, err)
	paths = append(paths, serialPaths...)
	serials := make(map[string]bool)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		certificate := parseCertificatePEM(t, data)
		if certificate.IsCA && bytes.Equal(certificate.RawSubject, certificate.RawIssuer) && certificate.CheckSignatureFrom(certificate) == nil {
			serials[storage.HexSerial(certificate.SerialNumber)] = true
		}
	}
	return serials
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func normalizeRequest(t *testing.T, path string) requestMeta {
	t.Helper()
	block, _ := pem.Decode(mustReadFile(t, path))
	require.NotNil(t, block)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, request.CheckSignature())
	algo, info := publicKeyDescription(request.PublicKey)
	meta := requestMeta{
		Name:          strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		CN:            request.Subject.CommonName,
		Country:       canonicalStrings(request.Subject.Country),
		Province:      canonicalStrings(request.Subject.Province),
		Locality:      canonicalStrings(request.Subject.Locality),
		Organizations: canonicalStrings(request.Subject.Organization),
		OrgUnits:      canonicalStrings(request.Subject.OrganizationalUnit),
		SubjectEmails: subjectEmailsFromName(request.Subject.Names),
		SubjectSerial: request.Subject.SerialNumber,
		DNS:           canonicalStrings(request.DNSNames),
		Emails:        canonicalStrings(request.EmailAddresses),
		PublicKeyAlgo: algo,
		PublicKeyInfo: info,
	}
	for _, ip := range request.IPAddresses {
		meta.IPs = append(meta.IPs, ip.String())
	}
	sort.Strings(meta.IPs)
	return meta
}

func parseCertificatePEM(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return certificate
}

func caIdentity(t *testing.T, dir string) certificateIdentity {
	t.Helper()
	certificate := parseCertificatePEM(t, mustReadFile(t, filepath.Join(dir, "ca.crt")))
	publicKeyDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	require.NoError(t, err)
	return certificateIdentity{
		Serial:       storage.HexSerial(certificate.SerialNumber),
		PublicKeyDER: publicKeyDER,
	}
}

func normalizePair(pair *cert.Pair) (pairMeta, error) {
	crt, err := pair.Certificate()
	if err != nil {
		return pairMeta{}, err
	}
	algo, info := publicKeySummary(crt)
	meta := pairMeta{
		Name:          pair.Name,
		CN:            crt.Subject.CommonName,
		Country:       canonicalStrings(crt.Subject.Country),
		Province:      canonicalStrings(crt.Subject.Province),
		Locality:      canonicalStrings(crt.Subject.Locality),
		Organizations: canonicalStrings(crt.Subject.Organization),
		OrgUnits:      canonicalStrings(crt.Subject.OrganizationalUnit),
		SubjectEmails: subjectEmails(crt),
		SubjectSerial: crt.Subject.SerialNumber,
		IsCA:          crt.IsCA,
		HasKey:        pair.HasKey(),
		DNS:           canonicalStrings(crt.DNSNames),
		Emails:        canonicalStrings(crt.EmailAddresses),
		NotAfterUnix:  crt.NotAfter.Unix(),
		PublicKeyAlgo: algo,
		PublicKeyInfo: info,
	}
	for _, ip := range crt.IPAddresses {
		meta.IPs = append(meta.IPs, ip.String())
	}
	sort.Strings(meta.IPs)
	if crt.IsCA {
		meta.Type = string(cert.CertTypeCA)
		return meta, nil
	}
	certType, err := pair.CertType()
	if err != nil {
		return pairMeta{}, err
	}
	meta.Type = string(certType)
	return meta, nil
}

func canonicalStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func subjectEmails(crt *x509.Certificate) []string {
	return subjectEmailsFromName(crt.Subject.Names)
}

func subjectEmailsFromName(names []pkix.AttributeTypeAndValue) []string {
	var out []string
	for _, attr := range names {
		if attr.Type.Equal(testEmailAddressOID) {
			if value, ok := attr.Value.(string); ok && value != "" {
				out = append(out, value)
			}
		}
	}
	sort.Strings(out)
	return out
}

func publicKeySummary(crt *x509.Certificate) (string, string) {
	return publicKeyDescription(crt.PublicKey)
}

func publicKeyDescription(publicKey any) (string, string) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return "rsa", strconv.Itoa(key.N.BitLen())
	case *ecdsa.PublicKey:
		return "ecdsa", key.Curve.Params().Name
	case ed25519.PublicKey:
		return "ed25519", strconv.Itoa(len(key))
	default:
		return "unknown", "unknown"
	}
}

func writeExternalCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn, Organization: []string{"External Org"}},
		DNSNames: []string{cn + ".example.test"},
	}, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), cn+".req")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), 0o644))
	return path
}

func assertKeyPassphrase(t *testing.T, dir, name, pass string) {
	t.Helper()
	pk, err := pki.NewWithFS(dir, pki.Config{})
	require.NoError(t, err)
	pair, err := pk.ShowCert(name)
	require.NoError(t, err)
	_, err = pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, pass)
	require.NoError(t, err)
	_, err = pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, "")
	require.Error(t, err)
}

func assertPlaintextKey(t *testing.T, dir, name string) {
	t.Helper()
	pk, err := pki.NewWithFS(dir, pki.Config{})
	require.NoError(t, err)
	pair, err := pk.ShowCert(name)
	require.NoError(t, err)
	_, err = pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, "")
	require.NoError(t, err)
}

func assertSequentialSerials(t *testing.T, dir string) {
	t.Helper()
	alice := parseCertificatePEM(t, mustReadFile(t, filepath.Join(dir, "issued", "alice.crt")))
	bob := parseCertificatePEM(t, mustReadFile(t, filepath.Join(dir, "issued", "bob.crt")))
	difference := new(big.Int).Sub(bob.SerialNumber, alice.SerialNumber)
	require.Zero(t, difference.Cmp(big.NewInt(1)))
}

func assertNonSequentialSerials(t *testing.T, dir string) {
	t.Helper()
	pk, err := pki.NewWithFS(dir, pki.Config{NoPass: true})
	require.NoError(t, err)
	alice, err := pk.ShowCert("alice")
	require.NoError(t, err)
	bob, err := pk.ShowCert("bob")
	require.NoError(t, err)
	aliceSN, err := alice.Serial()
	require.NoError(t, err)
	bobSN, err := bob.Serial()
	require.NoError(t, err)
	diff := new(big.Int).Abs(new(big.Int).Sub(bobSN, aliceSN))
	require.NotZero(t, diff.Cmp(big.NewInt(1)))
	require.GreaterOrEqual(t, aliceSN.BitLen(), 64)
	require.GreaterOrEqual(t, bobSN.BitLen(), 64)
}

func parseP12Meta(t *testing.T, data []byte, password string) p12Meta {
	t.Helper()
	key, certificate, caCerts, chainErr := gopkcs12.DecodeChain(data, password)
	if chainErr == nil {
		meta := p12Meta{}
		if key != nil {
			meta.KeyBlocks = 1
		}
		if certificate != nil {
			meta.CertCNs = append(meta.CertCNs, certificate.Subject.CommonName)
		}
		if key != nil && certificate != nil {
			publicKey, err := pkicrypto.PublicKey(key)
			require.NoError(t, err)
			keyDER, err := x509.MarshalPKIXPublicKey(publicKey)
			require.NoError(t, err)
			certificateDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
			require.NoError(t, err)
			meta.KeyMatchesCertificate = bytes.Equal(keyDER, certificateDER)
		}
		for _, crt := range caCerts {
			meta.CertCNs = append(meta.CertCNs, crt.Subject.CommonName)
		}
		sort.Strings(meta.CertCNs)
		return meta
	}

	certificates, trustErr := gopkcs12.DecodeTrustStore(data, password)
	if trustErr == nil {
		meta := p12Meta{}
		for _, crt := range certificates {
			meta.CertCNs = append(meta.CertCNs, crt.Subject.CommonName)
		}
		sort.Strings(meta.CertCNs)
		return meta
	}
	return parseP12MetaWithOpenSSL(t, data, password, chainErr, trustErr)
}

func parseP12MetaWithOpenSSL(t *testing.T, data []byte, password string, decodeErrors ...error) p12Meta {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.p12")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	args := []string{"pkcs12", "-in", path, "-passin", "pass:" + password, "-nodes"}
	output, err := exec.Command("openssl", args...).CombinedOutput()
	if err != nil {
		args = append(args, "-legacy")
		output, err = exec.Command("openssl", args...).CombinedOutput()
	}
	require.NoErrorf(t, err, "openssl decode failed: %s; Go decode errors: %v", output, decodeErrors)

	meta := p12Meta{}
	for len(output) > 0 {
		block, rest := pem.Decode(output)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			meta.CertCNs = append(meta.CertCNs, certificate.Subject.CommonName)
		default:
			if strings.Contains(block.Type, "PRIVATE KEY") {
				meta.KeyBlocks++
			}
		}
		output = rest
	}
	sort.Strings(meta.CertCNs)
	return meta
}

func hasLegacyPKCS12Profile(t *testing.T, data []byte, password string) bool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.p12")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	args := []string{"pkcs12", "-in", path, "-passin", "pass:" + password, "-info", "-noout", "-legacy"}
	output, err := exec.Command("openssl", args...).CombinedOutput()
	require.NoErrorf(t, err, "legacy PKCS#12 inspection failed: %s", output)
	text := strings.ToLower(string(output))
	return strings.Contains(text, "mac: sha1") && strings.Contains(text, "pbewithsha1")
}

func assertDHParametersValid(t *testing.T, data []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dh.pem")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	output, err := exec.Command("openssl", "dhparam", "-in", path, "-check", "-noout").CombinedOutput()
	require.NoErrorf(t, err, "invalid DH parameters: %s", output)
}

func parseCRL(t *testing.T, data []byte) *x509.RevocationList {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	return crl
}

func parseP7Meta(t *testing.T, data []byte) p7Meta {
	t.Helper()
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}
	parsed, err := pkcs7.Parse(data)
	require.NoError(t, err)
	meta := p7Meta{}
	for _, certificate := range parsed.Certificates {
		algo, info := publicKeySummary(certificate)
		meta.Certificates = append(meta.Certificates, p7CertificateMeta{
			CN:            certificate.Subject.CommonName,
			IsCA:          certificate.IsCA,
			PublicKeyAlgo: algo,
			PublicKeyInfo: info,
		})
	}
	sort.Slice(meta.Certificates, func(i, j int) bool { return meta.Certificates[i].CN < meta.Certificates[j].CN })
	return meta
}

func parsePEMKeyMeta(t *testing.T, data []byte, password string) pemKeyMeta {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	privateKey, err := pkicrypto.UnmarshalPrivateKey(data, password)
	require.NoError(t, err)
	publicKey, err := pkicrypto.PublicKey(privateKey)
	require.NoError(t, err)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	algo, info := publicKeyDescription(publicKey)
	return pemKeyMeta{
		Type:          block.Type,
		Encrypted:     block.Type == "ENCRYPTED PRIVATE KEY" || x509.IsEncryptedPEMBlock(block), //nolint:staticcheck // legacy PEM compatibility
		PublicKeyAlgo: algo,
		PublicKeyInfo: info,
		PublicKeyDER:  publicKeyDER,
	}
}

func assertPEMKeyParity(t *testing.T, easyRunner, goRunner binaryRunner, name string, easyData, goData []byte, password string) {
	t.Helper()
	easyMeta := parsePEMKeyMeta(t, easyData, password)
	goMeta := parsePEMKeyMeta(t, goData, password)
	require.Equal(t, easyMeta.Type, goMeta.Type)
	require.Equal(t, easyMeta.Encrypted, goMeta.Encrypted)
	require.Equal(t, easyMeta.PublicKeyAlgo, goMeta.PublicKeyAlgo)
	require.Equal(t, easyMeta.PublicKeyInfo, goMeta.PublicKeyInfo)
	require.Equal(t, certificatePublicKeyDER(t, easyRunner, name), easyMeta.PublicKeyDER)
	require.Equal(t, certificatePublicKeyDER(t, goRunner, name), goMeta.PublicKeyDER)
}

func certificatePublicKeyDER(t *testing.T, runner binaryRunner, name string) []byte {
	t.Helper()
	certificate := parseCertificatePEM(t, runner.readArtifact(t, "issued", name+".crt"))
	der, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	require.NoError(t, err)
	return der
}

func TestE2EHarnessRunnerPreservesArgvSeparatesStreamsAndSanitizesEnv(t *testing.T) {
	t.Setenv("EASYRSA", "parent-root")
	t.Setenv("EASYRSA_LEAK", "parent-secret")
	runner := binaryRunner{
		binary: os.Args[0],
		env: []string{
			"GO_EASYRSA_HELPER_PROCESS=1",
			"EASYRSA_EXPLICIT=first-value",
			"EASYRSA_EXPLICIT=child-value",
		},
	}
	argv := []string{"-test.run=TestE2EHelperProcess", "--", "--days=5", "build-ca"}
	result := runner.runCommand(argv...)

	require.NoError(t, result.err)
	require.Equal(t, argv, result.argv)
	require.Contains(t, result.stdout, "stdout:--days=5 build-ca")
	require.NotContains(t, result.stdout, "parent-secret")
	require.NotContains(t, result.stdout, "parent-root")
	require.Contains(t, result.stdout, "explicit:child-value")
	require.Contains(t, result.stderr, "stderr:--days=5 build-ca")
	require.NotContains(t, result.stdout, "stderr:")
	require.NotContains(t, result.stderr, "stdout:")
}

func TestE2EHarnessRejectsSplitUpstreamValueOption(t *testing.T) {
	err := validateCanonicalUpstreamArgs([]string{"--days", "5", "build-ca"})
	require.Error(t, err)
	require.NoError(t, validateCanonicalUpstreamArgs([]string{"--days=5", "build-ca"}))
}

func TestE2EHelperProcess(t *testing.T) {
	if os.Getenv("GO_EASYRSA_HELPER_PROCESS") != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		os.Exit(2)
	}
	args := strings.Join(os.Args[separator+1:], " ")
	_, _ = fmt.Fprintf(os.Stdout, "stdout:%s\n", args)
	_, _ = fmt.Fprintf(os.Stdout, "root:%s\n", os.Getenv("EASYRSA"))
	_, _ = fmt.Fprintf(os.Stdout, "leak:%s\n", os.Getenv("EASYRSA_LEAK"))
	_, _ = fmt.Fprintf(os.Stdout, "explicit:%s\n", os.Getenv("EASYRSA_EXPLICIT"))
	_, _ = fmt.Fprintf(os.Stderr, "stderr:%s\n", args)
	os.Exit(0)
}

func TestE2EHarnessNormalizesOnlySupersededExpiredStatus(t *testing.T) {
	index := []indexMeta{
		{Status: string(storage.StatusExpired), CN: "alice", Current: false},
		{Status: string(storage.StatusValid), CN: "alice", Current: true},
		{Status: string(storage.StatusExpired), CN: "bob", Current: true},
		{Status: string(storage.StatusRevoked), CN: "carol", Current: false},
	}

	normalizeRenewedIndexStatus(index)

	require.Equal(t, string(storage.StatusValid), index[0].Status)
	require.Equal(t, string(storage.StatusValid), index[1].Status)
	require.Equal(t, string(storage.StatusExpired), index[2].Status)
	require.Equal(t, string(storage.StatusRevoked), index[3].Status)
}

func TestFindRepoRoot(t *testing.T) {
	root := findRepoRoot(t)
	_, err := os.Stat(filepath.Join(root, ".git"))
	require.NoError(t, err)
}

func TestNormalizePairRejectsBadPEM(t *testing.T) {
	_, err := normalizePair(&cert.Pair{Name: "broken", CertPEM: []byte("not pem")})
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "decode")
}
