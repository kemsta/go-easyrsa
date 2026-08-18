package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func TestOutputPassword_RespectsNoPass(t *testing.T) {
	opts := defaultCLIOptions()
	opts.noPass = true
	opts.passOut = "pass:secret"

	got, err := outputPassword(&opts, map[string]bool{})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestOutputPassword_RequiresPassOutOrNoPass(t *testing.T) {
	opts := defaultCLIOptions()

	_, err := outputPassword(&opts, map[string]bool{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "passout")
}

func TestOutputPassword_RejectsEmptyPassPrefix(t *testing.T) {
	opts := defaultCLIOptions()
	opts.passOut = "pass:"

	_, err := outputPassword(&opts, map[string]bool{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not be empty")
}

func TestEffectivePassIn_PrefersFlagOverConfig(t *testing.T) {
	opts := defaultCLIOptions()
	opts.passIn = "pass:flag"

	got := effectivePassIn(&opts, pki.Config{KeyPassphrase: "cfg-key", CAPassphrase: "cfg-ca"})
	require.Equal(t, "flag", got)
}

func TestEffectivePassIn_UsesEnvPassIn(t *testing.T) {
	t.Setenv("EASYRSA_PASSIN", "pass:env-secret")

	opts := defaultCLIOptions()
	got := effectivePassIn(&opts, pki.Config{})
	require.Equal(t, "env-secret", got)
}

func TestEffectivePassIn_StripsOnePrefixAndPreservesWhitespace(t *testing.T) {
	t.Setenv("EASYRSA_PASSIN", "pass:pass:secret ")

	opts := defaultCLIOptions()
	got := effectivePassIn(&opts, pki.Config{})
	require.Equal(t, "pass:secret ", got)
}

func TestOutputPassword_UsesEnvPassOut(t *testing.T) {
	t.Setenv("EASYRSA_PASSOUT", "pass:env-secret")

	opts := defaultCLIOptions()
	got, err := outputPassword(&opts, map[string]bool{})
	require.NoError(t, err)
	require.Equal(t, "env-secret", got)
}

func TestCLI_ExportP1RejectsNonRSAKey(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "--algo", "ec", "--curve", "secp256r1", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "--algo", "ec", "--curve", "secp256r1", "build-client-full", "alice")
	require.NoError(t, err, out)
	_, err = runCLI(t, "--pki-dir", dir, "export-p1", "alice")
	require.Error(t, err)
	require.Contains(t, err.Error(), "RSA")
}

func TestCLI_ExportP12RejectsFriendlyNameCustomization(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	_, err = runCLI(t, "--pki-dir", dir, "--usefn", "custom-name", "export-p12", "alice")
	require.Error(t, err)
	require.Contains(t, err.Error(), "friendlyName")
}

func TestCLI_ExportP12RejectsEnvFriendlyNameCustomization(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_P12_FR_NAME", "custom-name")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)
	_, err = runCLI(t, "export-p12", "alice")
	require.Error(t, err)
	require.Contains(t, err.Error(), "friendlyName")
}

func TestCLI_ExportP12_NoCAOmitsCACert(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passout", "pass:exportpass", "export-p12", "alice", "noca")
	require.NoError(t, err, out)
	data := readCLIArtifact(t, dir, "private", "alice.p12")
	meta := parseLocalP12Meta(t, data, "exportpass")
	require.Equal(t, 1, meta.KeyBlocks)
	require.Equal(t, []string{"alice"}, meta.CertCNs)
}

func TestCLI_ExportP12_NoKeyProducesTrustStoreOnly(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passout", "pass:exportpass", "export-p12", "alice", "nokey")
	require.NoError(t, err, out)
	data := readCLIArtifact(t, dir, "private", "alice.p12")
	certs, err := gopkcs12.DecodeTrustStore(data, "exportpass")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(certs), 1)
}

func TestCLI_ExportP12_LegacyIsParseable(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passout", "pass:exportpass", "export-p12", "alice", "legacy")
	require.NoError(t, err, out)
	data := readCLIArtifact(t, dir, "private", "alice.p12")
	meta := parseLocalP12Meta(t, data, "exportpass")
	require.Equal(t, 1, meta.KeyBlocks)
	require.Contains(t, meta.CertCNs, "alice")
}

func TestCLI_ExportP12_NofnRejectsExplicitly(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	_, err = runCLI(t, "--pki-dir", dir, "export-p12", "alice", "nofn")
	require.Error(t, err)
	require.Contains(t, err.Error(), "friendlyName")
}

func TestCLI_ExportP7_NoCAOmitsCACert(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "export-p7", "alice", "noca")
	require.NoError(t, err, out)
	data := readCLIArtifact(t, dir, "issued", "alice.p7b")
	certCNs := parseLocalP7CertCNs(t, data)
	require.Equal(t, []string{"alice"}, certCNs)
}

func TestCLI_ExportP8WritesPrivateArtifact(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passout=pass:exportpass", "export-p8", "alice")
	require.NoError(t, err, out)

	data := readCLIArtifact(t, dir, "private", "alice.p8")
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Contains(t, block.Type, "PRIVATE KEY")
}

func readCLIArtifact(t *testing.T, dir string, path ...string) []byte {
	t.Helper()
	parts := append([]string{dir}, path...)
	data, err := os.ReadFile(filepath.Join(parts...))
	require.NoError(t, err)
	return data
}

type localP12Meta struct {
	KeyBlocks int
	CertCNs   []string
}

func parseLocalP12Meta(t *testing.T, data []byte, password string) localP12Meta {
	t.Helper()
	blocks, err := gopkcs12.ToPEM(data, password)
	require.NoError(t, err)
	meta := localP12Meta{}
	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			crt, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			meta.CertCNs = append(meta.CertCNs, crt.Subject.CommonName)
		default:
			if block.Type == "PRIVATE KEY" || block.Type == "ENCRYPTED PRIVATE KEY" || block.Type == "RSA PRIVATE KEY" {
				meta.KeyBlocks++
			}
		}
	}
	sort.Strings(meta.CertCNs)
	return meta
}

func parseLocalP7CertCNs(t *testing.T, data []byte) []string {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	parsed, err := pkcs7.Parse(block.Bytes)
	require.NoError(t, err)
	var certCNs []string
	for _, crt := range parsed.Certificates {
		certCNs = append(certCNs, crt.Subject.CommonName)
	}
	sort.Strings(certCNs)
	return certCNs
}
