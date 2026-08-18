package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestCLI_HelpDoesNotExposePassphrasesFromEnv(t *testing.T) {
	t.Setenv("EASYRSA_PASSIN", "pass:input-secret-xyz")
	t.Setenv("EASYRSA_PASSOUT", "pass:output-secret-xyz")

	out, err := runCLI(t, "--help")
	require.NoError(t, err)
	require.NotContains(t, out, "input-secret-xyz")
	require.NotContains(t, out, "output-secret-xyz")
}

func TestCLI_InvalidNumericEnvFailsBeforeCreatingPKI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_KEY_SIZE", "0")

	_, err := runCLI(t, "init-pki")
	require.Error(t, err)
	require.Contains(t, err.Error(), "EASYRSA_KEY_SIZE")
	_, statErr := os.Stat(dir)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestCLI_InvalidNumericFlagFailsBeforeCreatingPKI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")

	_, err := runCLI(t, "--pki-dir", dir, "--keysize=0", "init-pki")
	require.Error(t, err)
	require.Contains(t, err.Error(), "--keysize")
	_, statErr := os.Stat(dir)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestCLI_InvalidRSAKeySizeFailsBeforeCreatingPKI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")

	_, err := runCLI(t,
		"--pki-dir", dir,
		"--keysize=1",
		"--nopass",
		"build-ca",
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "RSA key size")
	_, statErr := os.Stat(dir)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestCLI_BuildCAAndClient(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)

	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	caPair, err := pk.ShowCA()
	require.NoError(t, err)
	require.True(t, caPair.HasKey())

	clientPair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	require.True(t, clientPair.HasKey())
	require.NoError(t, pk.VerifyCert("alice"))
}

func TestCLI_BuildCAUsesEasyRSADefaultCN(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	certificate, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, "Easy-RSA CA", certificate.Subject.CommonName)
}

func TestCLI_BuildCADefaultCNSentinelAndOverrides(t *testing.T) {
	tests := []struct {
		name     string
		reqCN    string
		command  []string
		expected string
	}{
		{name: "ChangeMe root", reqCN: "ChangeMe", command: []string{"build-ca"}, expected: "Easy-RSA CA"},
		{name: "ChangeMe sub CA", reqCN: "ChangeMe", command: []string{"build-ca", "subca"}, expected: "Easy-RSA Sub-CA"},
		{name: "explicit empty", reqCN: "", command: []string{"build-ca"}, expected: "Easy-RSA CA"},
		{name: "custom", reqCN: "Custom Root", command: []string{"build-ca"}, expected: "Custom Root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("EASYRSA_REQ_CN", tt.reqCN)
			args := append([]string{"--pki-dir", dir, "--nopass"}, tt.command...)
			out, err := runCLI(t, args...)
			require.NoError(t, err, out)
			pk := openFS(t, dir, pki.Config{NoPass: true})
			pair, err := pk.ShowCA()
			require.NoError(t, err)
			certificate, err := pair.Certificate()
			require.NoError(t, err)
			require.Equal(t, tt.expected, certificate.Subject.CommonName)
		})
	}
}

func TestCLI_UsesEnvBackedConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_ALGO", "ec")
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_ORG", "Acme Corp")
	t.Setenv("EASYRSA_NO_PASS", "1")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	key, err := pair.PrivateKey()
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok)

	certificate, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, []string{"Acme Corp"}, certificate.Subject.Organization)
}

func TestCLI_UsesEnvSubjectTemplateFields(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_COUNTRY", "DE")
	t.Setenv("EASYRSA_REQ_PROVINCE", "Berlin")
	t.Setenv("EASYRSA_REQ_CITY", "Berlin")
	t.Setenv("EASYRSA_REQ_ORG", "Acme Corp")
	t.Setenv("EASYRSA_REQ_OU", "PKI")
	t.Setenv("EASYRSA_REQ_EMAIL", "ops@example.test")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, []string{"DE"}, crt.Subject.Country)
	require.Equal(t, []string{"Berlin"}, crt.Subject.Province)
	require.Equal(t, []string{"Berlin"}, crt.Subject.Locality)
	require.Equal(t, []string{"Acme Corp"}, crt.Subject.Organization)
	require.Equal(t, []string{"PKI"}, crt.Subject.OrganizationalUnit)
	require.Contains(t, subjectEmailsFromCertificate(crt), "ops@example.test")
}

func TestCLI_FlagsOverrideEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_ALGO", "ec")
	t.Setenv("EASYRSA_NO_PASS", "1")

	out, err := runCLI(t, "--algo", "rsa", "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	key, err := pair.PrivateKey()
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PrivateKey)
	require.False(t, ok, "expected RSA key when flag overrides env")
}

func TestCLI_UsesEnvKeySizeForRSA(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_KEY_SIZE", "4096")
	t.Setenv("EASYRSA_NO_PASS", "1")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	key, err := pair.PrivateKey()
	require.NoError(t, err)
	rsaKey, ok := key.(*rsa.PrivateKey)
	require.True(t, ok, "expected RSA key")
	require.Equal(t, 4096, rsaKey.N.BitLen())
}

func TestCLI_KeySizeFlagOverridesEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_KEY_SIZE", "2048")
	t.Setenv("EASYRSA_NO_PASS", "1")

	out, err := runCLI(t, "--keysize", "3072", "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	key, err := pair.PrivateKey()
	require.NoError(t, err)
	rsaKey, ok := key.(*rsa.PrivateKey)
	require.True(t, ok, "expected RSA key")
	require.Equal(t, 3072, rsaKey.N.BitLen())
}

func TestCLI_GenDH_UsesEnvKeySize(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_KEY_SIZE", "256")

	out, err := runCLI(t, "gen-dh")
	require.NoError(t, err, out)
	dhPEM, err := os.ReadFile(filepath.Join(dir, "dh.pem"))
	require.NoError(t, err)
	require.Equal(t, 256, parseDHParameterBits(t, dhPEM))
}

func TestCLI_GenCRLWritesPKIArtifact(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "gen-crl")
	require.NoError(t, err, out)

	crlPEM, err := os.ReadFile(filepath.Join(dir, "crl.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(crlPEM)
	require.NotNil(t, block)
	_, err = x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
}

func TestCLI_SignReqCA_AppliesSubCAPathLen(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "gen-req", "sub1")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "--subca-len", "0", "sign-req", "ca", "sub1")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("sub1")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.True(t, crt.IsCA)
	require.True(t, crt.MaxPathLenZero)
	require.Equal(t, 0, crt.MaxPathLen)
}

func TestCLI_ExportP1WithPassOut_ProducesEncryptedRSAPrivateKey(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passout", "pass:test123", "export-p1", "alice")
	require.NoError(t, err, out)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "private", "alice.p1"))
	require.NoError(t, err)

	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)
	require.Equal(t, "RSA PRIVATE KEY", block.Type)
	require.True(t, x509.IsEncryptedPEMBlock(block))           //nolint:staticcheck // compatibility assertion
	der, err := x509.DecryptPEMBlock(block, []byte("test123")) //nolint:staticcheck // compatibility assertion
	require.NoError(t, err)
	_, err = x509.ParsePKCS1PrivateKey(der)
	require.NoError(t, err)
}

func TestCLI_NoPassAlias_WorksLikeNoPass(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--no-pass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--no-pass", "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	_, err = pair.PrivateKey()
	require.NoError(t, err)
}

func TestCLI_SubjectAltNameAlias_AppliesSAN(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "--subject-alt-name", "DNS:alias.example.test", "build-server-full", "vpn")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("vpn")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, []string{"alias.example.test"}, crt.DNSNames)
}

func TestCLI_SANFlagsAccumulateWithEnvSAN(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_SAN", "DNS:env.example.test")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--san=DNS:flag.example.test", "build-server-full", "vpn")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("vpn")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"env.example.test", "flag.example.test"}, crt.DNSNames)
}

func TestCLI_MixedSANAliasesAccumulate(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t,
		"--pki-dir", dir,
		"--nopass",
		"--san=DNS:first.example.test",
		"--subject-alt-name=DNS:second.example.test",
		"build-server-full", "vpn",
	)
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("vpn")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"first.example.test", "second.example.test"}, crt.DNSNames)
}

func TestCLI_ExpireMovesCertificateWithoutChangingIndexStatus(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)

	out, err = runCLI(t, "--pki-dir", dir, "expire", "alice")
	require.NoError(t, err, out)
	require.NoFileExists(t, filepath.Join(dir, "issued", "alice.crt"))
	require.FileExists(t, filepath.Join(dir, "expired", "alice.crt"))
	requireIndexStatus(t, dir, "alice", storage.StatusValid)
}

func TestCLI_ExpireRejectsForeignDirectory(t *testing.T) {
	dir := t.TempDir()
	issued := filepath.Join(dir, "issued")
	require.NoError(t, os.MkdirAll(issued, 0o755))
	path := filepath.Join(issued, "alice.crt")
	require.NoError(t, os.WriteFile(path, []byte("foreign"), 0o644))

	_, err := runCLI(t, "--pki-dir", dir, "expire", "alice")
	require.Error(t, err)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, []byte("foreign"), data)
	require.NoFileExists(t, filepath.Join(dir, "expired", "alice.crt"))
}

func TestCLI_RevokeIssuedArchivesCurrentFiles(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	hexSerial := storage.HexSerial(serial)
	for _, args := range [][]string{
		{"--pki-dir", dir, "export-p12", "alice", "nopass"},
		{"--pki-dir", dir, "export-p7", "alice"},
		{"--pki-dir", dir, "export-p8", "alice", "nopass"},
		{"--pki-dir", dir, "export-p1", "alice", "nopass"},
	} {
		out, err = runCLI(t, args...)
		require.NoError(t, err, out)
	}

	out, err = runCLI(t, "--pki-dir", dir, "revoke-issued", "alice")
	require.NoError(t, err, out)
	require.NoFileExists(t, filepath.Join(dir, "issued", "alice.crt"))
	require.NoFileExists(t, filepath.Join(dir, "private", "alice.key"))
	require.FileExists(t, filepath.Join(dir, "revoked", "certs_by_serial", hexSerial+".crt"))
	require.FileExists(t, filepath.Join(dir, "revoked", "private_by_serial", hexSerial+".key"))
	require.FileExists(t, filepath.Join(dir, "revoked", "reqs_by_serial", hexSerial+".req"))
	for _, path := range []string{
		filepath.Join(dir, "private", "alice.p12"),
		filepath.Join(dir, "issued", "alice.p7b"),
		filepath.Join(dir, "private", "alice.p8"),
		filepath.Join(dir, "private", "alice.p1"),
	} {
		require.NoFileExists(t, path)
	}
	requireIndexStatus(t, dir, "alice", storage.StatusRevoked)
}

func TestCLI_RevokeExpiredArchivesExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	hexSerial := storage.HexSerial(serial)

	out, err = runCLI(t, "--pki-dir", dir, "expire", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "revoke-expired", "alice")
	require.NoError(t, err, out)
	require.NoFileExists(t, filepath.Join(dir, "expired", "alice.crt"))
	require.FileExists(t, filepath.Join(dir, "revoked", "certs_by_serial", hexSerial+".crt"))
	require.FileExists(t, filepath.Join(dir, "private", "alice.key"))
	require.FileExists(t, filepath.Join(dir, "reqs", "alice.req"))
	requireIndexStatus(t, dir, "alice", storage.StatusRevoked)
}

func TestCLI_RevokeArchiveConflictLeavesCurrentStateUntouched(t *testing.T) {
	tests := []struct {
		name          string
		directory     string
		extension     string
		missingSource string
	}{
		{name: "certificate", directory: "certs_by_serial", extension: ".crt"},
		{name: "private key", directory: "private_by_serial", extension: ".key"},
		{name: "request", directory: "reqs_by_serial", extension: ".req"},
		{name: "missing private key", directory: "private_by_serial", extension: ".key", missingSource: filepath.Join("private", "alice.key")},
		{name: "missing request", directory: "reqs_by_serial", extension: ".req", missingSource: filepath.Join("reqs", "alice.req")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
			require.NoError(t, err, out)
			out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
			require.NoError(t, err, out)
			pk := openFS(t, dir, pki.Config{NoPass: true})
			pair, err := pk.ShowCert("alice")
			require.NoError(t, err)
			serial, err := pair.Serial()
			require.NoError(t, err)
			hexSerial := storage.HexSerial(serial)
			if tt.missingSource != "" {
				require.NoError(t, os.Remove(filepath.Join(dir, tt.missingSource)))
			}
			conflict := filepath.Join(dir, "revoked", tt.directory, hexSerial+tt.extension)
			require.NoError(t, os.MkdirAll(filepath.Dir(conflict), 0o755))
			require.NoError(t, os.WriteFile(conflict, []byte("conflict"), 0o600))

			_, err = runCLI(t, "--pki-dir", dir, "revoke-issued", "alice")
			require.Error(t, err)
			require.FileExists(t, filepath.Join(dir, "issued", "alice.crt"))
			for _, source := range []string{filepath.Join("private", "alice.key"), filepath.Join("reqs", "alice.req")} {
				if source == tt.missingSource {
					require.NoFileExists(t, filepath.Join(dir, source))
				} else {
					require.FileExists(t, filepath.Join(dir, source))
				}
			}
			if tt.directory != "certs_by_serial" {
				require.NoFileExists(t, filepath.Join(dir, "revoked", "certs_by_serial", hexSerial+".crt"))
			}
			if tt.directory == "reqs_by_serial" {
				require.NoFileExists(t, filepath.Join(dir, "revoked", "private_by_serial", hexSerial+".key"))
			}
			requireIndexStatus(t, dir, "alice", storage.StatusValid)
			data, readErr := os.ReadFile(conflict)
			require.NoError(t, readErr)
			require.Equal(t, []byte("conflict"), data)
		})
	}
}

func TestCLI_RevokeExpiredRejectsInvalidEntityNames(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)

	for _, name := range []string{"../ca", "../issued/alice", filepath.Join(dir, "ca")} {
		_, err := runCLI(t, "--pki-dir", dir, "revoke-expired", name)
		require.Error(t, err)
	}
	require.FileExists(t, filepath.Join(dir, "ca.crt"))
	requireIndexStatus(t, dir, "Easy-RSA CA", storage.StatusValid)
}

func TestCLI_ExpireRejectsSymlinkedSource(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)

	issued := filepath.Join(dir, "issued", "alice.crt")
	outside := filepath.Join(t.TempDir(), "outside.crt")
	data, err := os.ReadFile(issued)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(outside, data, 0o600))
	require.NoError(t, os.Remove(issued))
	if err := os.Symlink(outside, issued); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err = runCLI(t, "--pki-dir", dir, "expire", "alice")
	require.Error(t, err)
	require.FileExists(t, outside)
	require.NoFileExists(t, filepath.Join(dir, "expired", "alice.crt"))
}

func TestCLI_MutatingCommandsHonorSharedLock(t *testing.T) {
	dir := t.TempDir()
	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	lock, err := acquirePKIMutationLock(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, lock.Unlock()) }()

	for _, args := range [][]string{
		{"--pki-dir", dir, "renew", "alice"},
		{"--pki-dir", dir, "gen-crl"},
		{"--pki-dir", dir, "--nopass", "build-client-full", "bob"},
	} {
		_, err := runCLI(t, args...)
		require.Error(t, err)
		require.Contains(t, err.Error(), "mutation is in progress")
	}
}

func TestCLI_ShowExpire_AcceptsDaysArgument(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "fresh")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "--startdate", "20200101000000Z", "--enddate", "20200102000000Z", "build-client-full", "old1")
	require.NoError(t, err, out)

	out, err = runCLI(t, "--pki-dir", dir, "show-expire", "1")
	require.NoError(t, err, out)
	require.Contains(t, strings.ToLower(out), "old1")
	require.NotContains(t, strings.ToLower(out), "fresh")
}

func TestCLI_ShowExpire_UsesEnvPreExpiryWindow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_CERT_EXPIRE", "5")
	t.Setenv("EASYRSA_PRE_EXPIRY_WINDOW", "10")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "soon")
	require.NoError(t, err, out)
	out, err = runCLI(t, "show-expire")
	require.NoError(t, err, out)
	require.Contains(t, strings.ToLower(out), "soon")
}

func TestCLI_DaysFlagOverridesEnvCertExpire(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_CERT_EXPIRE", "30")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--days", "5", "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	days := int(crt.NotAfter.Sub(crt.NotBefore).Hours() / 24)
	require.GreaterOrEqual(t, days, 4)
	require.LessOrEqual(t, days, 6)
}

func TestCLI_StartAndEndDateFlagsOverrideEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_START_DATE", "20200101000000Z")
	t.Setenv("EASYRSA_END_DATE", "20200102000000Z")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--startdate", "20240101000000Z", "--enddate", "20240103000000Z", "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, "2024-01-01T00:00:00Z", crt.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	require.Equal(t, "2024-01-03T00:00:00Z", crt.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
}

func TestCLI_UsesEnvDNModeCNOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_DN", "cn_only")
	t.Setenv("EASYRSA_REQ_ORG", "Acme Corp")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Empty(t, crt.Subject.Organization)
}

func TestCLI_UsesEnvReqCNAndAutoSAN(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_REQ_CN", "env.example.test")
	t.Setenv("EASYRSA_AUTO_SAN", "1")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-server-full", "vpn")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("vpn")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, "env.example.test", crt.Subject.CommonName)
	require.Equal(t, []string{"env.example.test"}, crt.DNSNames)
}

func TestCLI_EnvReqSerialIsIgnoredInCNOnlyMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_REQ_SERIAL", "SER-42")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Empty(t, crt.Subject.SerialNumber)
}

func TestCLI_RequestFlagsAndDNMode_AffectSubject(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t,
		"--pki-dir", dir,
		"--nopass",
		"--dn-mode", "org",
		"--req-cn", "vpn.example.test",
		"--req-c", "DE",
		"--req-st", "Berlin",
		"--req-city", "Berlin",
		"--req-org", "Acme Corp",
		"--req-email", "ops@example.test",
		"--req-ou", "PKI",
		"--req-serial", "SER-99",
		"build-server-full", "vpn",
	)
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("vpn")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, "vpn.example.test", crt.Subject.CommonName)
	require.Equal(t, []string{"DE"}, crt.Subject.Country)
	require.Equal(t, []string{"Berlin"}, crt.Subject.Province)
	require.Equal(t, []string{"Berlin"}, crt.Subject.Locality)
	require.Equal(t, []string{"Acme Corp"}, crt.Subject.Organization)
	require.Equal(t, []string{"PKI"}, crt.Subject.OrganizationalUnit)
	require.Equal(t, "SER-99", crt.Subject.SerialNumber)
}

func TestCLI_UsesEnvRandSN(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_RAND_SN", "yes")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "bob")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
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
}

func TestCLI_ExplicitNoPassFalseOverridesEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_NO_PASS", "true")

	out, err := runCLI(t,
		"--pki-dir", dir,
		"--nopass=false",
		"--passout=pass:secret123",
		"build-ca",
	)
	require.NoError(t, err, out)

	keyPEM, err := os.ReadFile(filepath.Join(dir, "private", "ca.key"))
	require.NoError(t, err)
	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)
	require.Equal(t, "ENCRYPTED PRIVATE KEY", block.Type)
	_, err = pkicrypto.UnmarshalPrivateKey(keyPEM, "secret123")
	require.NoError(t, err)
}

func TestCLI_UsesEnvNoPassForPlaintextKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	_, err = pair.PrivateKey()
	require.NoError(t, err)
}

func TestCLI_UsesEnvSANOnBuildServerFull(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_SAN", "DNS:env.example.test,IP:127.0.0.1,EMAIL:ops@example.test")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-server-full", "vpn")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("vpn")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, []string{"env.example.test"}, crt.DNSNames)
	require.Len(t, crt.IPAddresses, 1)
	require.Equal(t, "127.0.0.1", crt.IPAddresses[0].String())
	require.Equal(t, []string{"ops@example.test"}, crt.EmailAddresses)
}

func TestCLI_UsesEnvCopyExtOnSignReq(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_CP_EXT", "1")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--san", "DNS:csr.example.test", "gen-req", "srv1")
	require.NoError(t, err, out)
	out, err = runCLI(t, "sign-req", "server", "srv1")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("srv1")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, []string{"csr.example.test"}, crt.DNSNames)
}

func TestCLI_UsesEnvCAAndCertExpire(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_CA_EXPIRE", "3651")
	t.Setenv("EASYRSA_CERT_EXPIRE", "30")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	caPair, err := pk.ShowCA()
	require.NoError(t, err)
	caCert, err := caPair.Certificate()
	require.NoError(t, err)
	clientPair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	clientCert, err := clientPair.Certificate()
	require.NoError(t, err)
	require.GreaterOrEqual(t, int(caCert.NotAfter.Sub(caCert.NotBefore).Hours()/24), 3650)
	require.GreaterOrEqual(t, int(clientCert.NotAfter.Sub(clientCert.NotBefore).Hours()/24), 29)
}

func TestCLI_UsesEnvStartDateEndDate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_START_DATE", "20240101000000Z")
	t.Setenv("EASYRSA_END_DATE", "20240102000000Z")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("alice")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, "2024-01-01T00:00:00Z", crt.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	require.Equal(t, "2024-01-02T00:00:00Z", crt.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
}

func TestCLI_UsesEnvSubcaLenOnSignReqCA(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_SUBCA_LEN", "0")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "gen-req", "sub1")
	require.NoError(t, err, out)
	out, err = runCLI(t, "sign-req", "ca", "sub1")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("sub1")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.True(t, crt.IsCA)
	require.True(t, crt.MaxPathLenZero)
	require.Equal(t, 0, crt.MaxPathLen)
}

func TestCLI_UsesEnvNewSubjectOnSignReq(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_NEW_SUBJECT", "/CN=replaced/O=Acme")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "gen-req", "client1")
	require.NoError(t, err, out)
	out, err = runCLI(t, "sign-req", "client", "client1", "newsubj")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("client1")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, "replaced", crt.Subject.CommonName)
	require.Equal(t, []string{"Acme"}, crt.Subject.Organization)
}

func TestCLI_UsesEnvPassInPassOutForExportP1(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_PASSOUT", "pass:secret123")
	t.Setenv("EASYRSA_PASSIN", "pass:secret123")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "export-p1", "alice")
	require.NoError(t, err, out)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "private", "alice.p1"))
	require.NoError(t, err)

	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)
	require.Equal(t, "RSA PRIVATE KEY", block.Type)
	require.True(t, x509.IsEncryptedPEMBlock(block))
	der, err := x509.DecryptPEMBlock(block, []byte("secret123")) //nolint:staticcheck // compatibility assertion
	require.NoError(t, err)
	_, err = x509.ParsePKCS1PrivateKey(der)
	require.NoError(t, err)
}

func TestCLI_PassInFlagDecryptsEncryptedKeyForExport(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--passout", "pass:secret123", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passin", "pass:secret123", "--passout", "pass:secret123", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passin", "pass:secret123", "export-p1", "alice", "nopass")
	require.NoError(t, err, out)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "private", "alice.p1"))
	require.NoError(t, err)

	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block)
	require.Equal(t, "RSA PRIVATE KEY", block.Type)
}

func TestCLI_SetPassFailsWithWrongPassIn(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--passout", "pass:secret123", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passin", "pass:secret123", "--passout", "pass:secret123", "build-client-full", "alice")
	require.NoError(t, err, out)
	_, err = runCLI(t, "--pki-dir", dir, "--passin", "pass:wrong", "--passout", "pass:newsecret", "set-pass", "alice")
	require.Error(t, err)
}

func TestCLI_SetPassRequiresExplicitOutputProtection(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--passout", "pass:secret123", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--passin", "pass:secret123", "--passout", "pass:secret123", "build-client-full", "alice")
	require.NoError(t, err, out)

	keyPath := filepath.Join(dir, "private", "alice.key")
	before, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	_, err = runCLI(t, "--pki-dir", dir, "--passin", "pass:secret123", "set-pass", "alice")
	require.Error(t, err)
	require.Contains(t, err.Error(), "passout")

	after, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, before, after)

	_, err = runCLI(t,
		"--pki-dir", dir,
		"--passin", "pass:secret123",
		"--passout=pass:",
		"set-pass", "alice",
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not be empty")

	afterEmptyPass, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, before, afterEmptyPass)
}

func TestCLI_PreserveTokenPreservesCSRSubject(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_ORG", "Request Org")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "gen-req", "client1")
	require.NoError(t, err, out)
	out, err = runCLI(t, "sign-req", "client", "client1", "preserve")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("client1")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, []string{"Request Org"}, crt.Subject.Organization)
}

func TestCLI_UsesEnvPreserveDNOnSignReq(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_PRESERVE_DN", "1")
	t.Setenv("EASYRSA_DN", "org")
	t.Setenv("EASYRSA_REQ_ORG", "Request Org")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "gen-req", "client1")
	require.NoError(t, err, out)
	out, err = runCLI(t, "sign-req", "client", "client1")
	require.NoError(t, err, out)

	pk := openFS(t, dir, pki.Config{NoPass: true})
	pair, err := pk.ShowCert("client1")
	require.NoError(t, err)
	crt, err := pair.Certificate()
	require.NoError(t, err)
	require.Equal(t, []string{"Request Org"}, crt.Subject.Organization)
}

func TestCLI_UsesEnvBatchOnVerifyCert(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_BATCH", "1")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "verify-cert", "alice")
	require.NoError(t, err, out)
	require.Contains(t, out, "OK")
}

func TestCLI_VerifyCertRejectsUnknownCommandOption(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	_, err = runCLI(t, "--pki-dir", dir, "verify-cert", "alice", "wat")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown command option")
}

func TestCLI_ShowCertAcceptsFullTokenAndRejectsUnknownToken(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "--nopass", "build-client-full", "alice")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "show-cert", "alice", "full")
	require.NoError(t, err, out)
	_, err = runCLI(t, "--pki-dir", dir, "show-cert", "alice", "wat")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown command option")
}

func TestCLI_ShowCAAcceptsFullTokenAndRejectsUnknownToken(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca")
	require.NoError(t, err, out)
	out, err = runCLI(t, "--pki-dir", dir, "show-ca", "full")
	require.NoError(t, err, out)
	_, err = runCLI(t, "--pki-dir", dir, "show-ca", "wat")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown command option")
}

func TestCLI_GenReqRejectsDeferredTextToken(t *testing.T) {
	dir := t.TempDir()

	_, err := runCLI(t, "--pki-dir", dir, "--nopass", "gen-req", "alice", "text")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown command option")
}

func TestCLI_RejectsUnsupportedEnvForNonBuildCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_DIGEST", "sha512")

	_, err := runCLI(t, "--pki-dir", dir, "gen-crl")
	require.Error(t, err)
	require.Contains(t, err.Error(), "EASYRSA_DIGEST")
}

func TestCLI_BuildCARejectsRawCAEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_RAW_CA", "1")

	_, err := runCLI(t, "build-ca")
	require.Error(t, err)
	require.Contains(t, err.Error(), "raw CA password input")
}

func TestCLI_BuildCARejectsRawCAToken(t *testing.T) {
	dir := t.TempDir()

	_, err := runCLI(t, "--pki-dir", dir, "--nopass", "build-ca", "rawca")
	require.Error(t, err)
	require.Contains(t, err.Error(), "raw CA password input")
}

func TestCLI_RejectsUnsupportedResultAffectingEnvRequests(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
	}{
		{name: "digest", env: "EASYRSA_DIGEST", value: "sha512"},
		{name: "basic constraints critical", env: "EASYRSA_BC_CRIT", value: "1"},
		{name: "key usage critical", env: "EASYRSA_KU_CRIT", value: "1"},
		{name: "extended key usage critical", env: "EASYRSA_EKU_CRIT", value: "1"},
		{name: "san critical", env: "EASYRSA_SAN_CRIT", value: "1"},
		{name: "netscape support", env: "EASYRSA_NS_SUPPORT", value: "1"},
		{name: "netscape comment", env: "EASYRSA_NS_COMMENT", value: "legacy comment"},
		{name: "extra exts", env: "EASYRSA_EXTRA_EXTS", value: "subjectAltName=DNS:test"},
		{name: "alias days", env: "EASYRSA_ALIAS_DAYS", value: "30"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("EASYRSA_PKI", dir)
			t.Setenv("EASYRSA_NO_PASS", "1")
			t.Setenv(tt.env, tt.value)
			_, err := runCLI(t, "build-ca")
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.env)
		})
	}
}

func TestCLI_StrictUnsupportedEnvParityCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EASYRSA_PKI", dir)
	t.Setenv("EASYRSA_NO_PASS", "1")
	t.Setenv("EASYRSA_DIGEST", "sha512")
	t.Setenv("GO_EASYRSA_STRICT_ENV_PARITY", "0")

	out, err := runCLI(t, "build-ca")
	require.NoError(t, err, out)
}

func requireIndexStatus(t *testing.T, dir, name string, expected storage.CertStatus) {
	t.Helper()
	pk := openFS(t, dir, pki.Config{NoPass: true})
	snapshot, err := pk.ExportSnapshot()
	require.NoError(t, err)
	for _, entry := range snapshot.Index {
		if entry.Subject.CommonName == name {
			require.Equal(t, expected, entry.Status)
			return
		}
	}
	t.Fatalf("index entry for %s not found", name)
}

func subjectEmailsFromCertificate(crt *x509.Certificate) []string {
	var out []string
	for _, attr := range crt.Subject.Names {
		if attr.Type.String() == "1.2.840.113549.1.9.1" {
			if value, ok := attr.Value.(string); ok && value != "" {
				out = append(out, value)
			}
		}
	}
	return out
}
