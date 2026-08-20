package main

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestRenewedCommandsRegistered(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	for _, name := range []string{"show-renew", "revoke-renewed"} {
		command, _, err := root.Find([]string{name})
		require.NoError(t, err)
		require.Equal(t, name, command.Name())
	}
}

func TestCLIShowAndRevokeRenewed(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	runRenewedCLI(t, pkiDir, "init-pki")
	runRenewedCLI(t, pkiDir, "--nopass", "--keysize=1024", "build-ca")
	runRenewedCLI(t, pkiDir, "--nopass", "--keysize=1024", "build-client-full", "alice")
	oldPEM := mustReadRenewedCLIFile(t, pkiDir, "issued", "alice.crt")
	oldSerial, err := (&cert.Pair{Name: "alice", CertPEM: oldPEM}).Serial()
	require.NoError(t, err)
	runRenewedCLI(t, pkiDir, "renew", "alice")
	currentCertificate := mustReadRenewedCLIFile(t, pkiDir, "issued", "alice.crt")
	currentKey := mustReadRenewedCLIFile(t, pkiDir, "private", "alice.key")
	currentRequest := mustReadRenewedCLIFile(t, pkiDir, "reqs", "alice.req")
	writeRenewedCLIArtifacts(t, pkiDir, "alice")
	runRenewedCLI(t, pkiDir, "gen-crl")
	crlBefore := mustReadRenewedCLIFile(t, pkiDir, "crl.pem")

	output := runRenewedCLI(t, pkiDir, "show-renew")
	require.Contains(t, output, "V | Serial: "+storage.HexSerial(oldSerial))
	require.Contains(t, output, "CN: alice")
	require.NotContains(t, output, "***")
	filtered := runRenewedCLI(t, pkiDir, "show-renew", "alice")
	require.Equal(t, output, filtered)
	missing := runRenewedCLI(t, pkiDir, "show-renew", "missing")
	require.Empty(t, missing)
	_, err = runCLI(t, "--pki-dir", pkiDir, "show-renew", "alice", "extra")
	require.Error(t, err)

	runRenewedCLI(t, pkiDir, "revoke-renewed", "alice", "certificateHold")
	require.Equal(t, currentCertificate, mustReadRenewedCLIFile(t, pkiDir, "issued", "alice.crt"))
	require.Equal(t, currentKey, mustReadRenewedCLIFile(t, pkiDir, "private", "alice.key"))
	require.Equal(t, currentRequest, mustReadRenewedCLIFile(t, pkiDir, "reqs", "alice.req"))
	for _, artifact := range renewedCLIArtifactPaths("alice") {
		_, err := os.Stat(filepath.Join(pkiDir, filepath.FromSlash(artifact)))
		require.ErrorIs(t, err, os.ErrNotExist, artifact)
	}
	require.Equal(t, crlBefore, mustReadRenewedCLIFile(t, pkiDir, "crl.pem"))
	require.NoFileExists(t, filepath.Join(pkiDir, "renewed", "issued", "alice.crt"))
	require.Equal(t, oldPEM, mustReadRenewedCLIFile(t, pkiDir, "revoked", "certs_by_serial", storage.HexSerial(oldSerial)+".crt"))
	require.Empty(t, runRenewedCLI(t, pkiDir, "show-renew"))

	pk, err := pki.OpenWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	entry, err := pk.CheckSerial(oldSerial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusRevoked, entry.Status)
	require.Equal(t, cert.ReasonCertificateHold, entry.RevocationReason)
	runRenewedCLI(t, pkiDir, "gen-crl")
	crl := parseRenewedCLICRL(t, mustReadRenewedCLIFile(t, pkiDir, "crl.pem"))
	require.Len(t, crl.RevokedCertificateEntries, 1)
	require.Equal(t, int(cert.ReasonCertificateHold), crl.RevokedCertificateEntries[0].ReasonCode)
	runRenewedCLI(t, pkiDir, "renew", "alice")
}

func TestCLIShowRenewedHistoricalArchive(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "pki")
	runRenewedCLI(t, pkiDir, "init-pki")
	runRenewedCLI(t, pkiDir, "--nopass", "--keysize=1024", "build-ca")
	runRenewedCLI(t, pkiDir, "--nopass", "--keysize=1024", "build-client-full", "alice")
	oldPEM := mustReadRenewedCLIFile(t, pkiDir, "issued", "alice.crt")
	oldSerial, err := (&cert.Pair{Name: "alice", CertPEM: oldPEM}).Serial()
	require.NoError(t, err)
	runRenewedCLI(t, pkiDir, "renew", "alice")
	historicalDir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
	require.NoError(t, os.MkdirAll(historicalDir, 0o755))
	require.NoError(t, os.Rename(
		filepath.Join(pkiDir, "renewed", "issued", "alice.crt"),
		filepath.Join(historicalDir, storage.HexSerial(oldSerial)+".crt"),
	))

	output := runRenewedCLI(t, pkiDir, "show-renew", "alice")
	require.True(t, strings.HasPrefix(output, "*** V | Serial: "))
	require.Contains(t, output, "CN: alice")
	_, err = runCLI(t, "--pki-dir", pkiDir, "revoke-renewed", "alice")
	require.Error(t, err)
	require.FileExists(t, filepath.Join(historicalDir, storage.HexSerial(oldSerial)+".crt"))
}

func TestCLIShowRenewedDoesNotInitializeMissingPKI(t *testing.T) {
	pkiDir := filepath.Join(t.TempDir(), "missing")
	_, err := runCLI(t, "--pki-dir", pkiDir, "show-renew")
	require.Error(t, err)
	_, statErr := os.Stat(pkiDir)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestParseReasonAcceptsEasyRSAFamilies(t *testing.T) {
	t.Parallel()
	tests := map[string]cert.RevocationReason{
		"":                   cert.ReasonUnspecified,
		"us":                 cert.ReasonUnspecified,
		"uns":                cert.ReasonUnspecified,
		"unspecified":        cert.ReasonUnspecified,
		"kc":                 cert.ReasonKeyCompromise,
		"key-anything":       cert.ReasonKeyCompromise,
		"cc":                 cert.ReasonCACompromise,
		"CACompromise":       cert.ReasonCACompromise,
		"ac":                 cert.ReasonAffiliationChanged,
		"affiliationChanged": cert.ReasonAffiliationChanged,
		"ss":                 cert.ReasonSuperseded,
		"superseded":         cert.ReasonSuperseded,
		"co":                 cert.ReasonCessationOfOperation,
		"cessation":          cert.ReasonCessationOfOperation,
		"ch":                 cert.ReasonCertificateHold,
		"certificateHold":    cert.ReasonCertificateHold,
		"  CER-prefix  ":     cert.ReasonCertificateHold,
	}
	for value, want := range tests {
		got, err := parseReason(value)
		require.NoError(t, err, value)
		require.Equal(t, want, got, value)
	}
	for _, value := range []string{"u", "k", "hold", "removeFromCRL"} {
		_, err := parseReason(value)
		require.Error(t, err, value)
	}
}

func TestRenewalFormattingAndExactCNFiltering(t *testing.T) {
	t.Parallel()
	renewals := []pki.RenewalInfo{
		{
			Name:       "storage-one",
			Serial:     newSerial(1),
			Status:     storage.StatusValid,
			ExpiresAt:  time.Date(2030, time.January, 2, 3, 4, 5, 0, time.FixedZone("offset", 3600)),
			CommonName: "Alpha",
		},
		{
			Name:           "storage-two",
			Serial:         newSerial(255),
			Status:         storage.StatusExpired,
			ExpiresAt:      time.Date(2020, time.December, 31, 23, 59, 58, 0, time.UTC),
			CommonName:     "beta",
			RequiresRewind: true,
		},
	}
	command := newRootCmd()
	var output strings.Builder
	command.SetOut(&output)
	require.NoError(t, printRenewalList(command, renewals))
	require.Equal(t,
		"V | Serial: 01 | Expires: Jan  2 02:04:05 2030 GMT | CN: Alpha\n"+
			"*** E | Serial: FF | Expires: Dec 31 23:59:58 2020 GMT | CN: beta\n",
		output.String(),
	)

	filtered := filterRenewalsByCommonName(renewals, "Alpha")
	require.Len(t, filtered, 1)
	require.Equal(t, "storage-one", filtered[0].Name)
	for _, target := range []string{"storage-one", "alpha", "Alph"} {
		require.Empty(t, filterRenewalsByCommonName(renewals, target), target)
	}
}

func TestPrintRenewalListPropagatesWriteFailure(t *testing.T) {
	t.Parallel()
	command := newRootCmd()
	command.SetOut(errorWriter{})
	err := printRenewalList(command, []pki.RenewalInfo{{
		Serial:     newSerial(1),
		Status:     storage.StatusValid,
		ExpiresAt:  timeForRenewedCLITest(),
		CommonName: "alice",
	}})
	require.Error(t, err)
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func runRenewedCLI(t *testing.T, pkiDir string, args ...string) string {
	t.Helper()
	arguments := append([]string{"--pki-dir", pkiDir}, args...)
	output, err := runCLI(t, arguments...)
	require.NoError(t, err, "%v: %s", arguments, output)
	return output
}

func writeRenewedCLIArtifacts(t *testing.T, pkiDir, name string) {
	t.Helper()
	for _, artifact := range renewedCLIArtifactPaths(name) {
		path := filepath.Join(pkiDir, filepath.FromSlash(artifact))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(artifact), 0o600))
	}
}

func renewedCLIArtifactPaths(name string) []string {
	return []string{
		"private/" + name + ".p12",
		"private/" + name + ".p8",
		"private/" + name + ".p1",
		"issued/" + name + ".p7b",
		"inline/" + name + ".inline",
		"inline/private/" + name + ".inline",
	}
}

func mustReadRenewedCLIFile(t *testing.T, pkiDir string, path ...string) []byte {
	t.Helper()
	parts := append([]string{pkiDir}, path...)
	data, err := os.ReadFile(filepath.Join(parts...))
	require.NoError(t, err)
	return data
}

func parseRenewedCLICRL(t *testing.T, data []byte) *x509.RevocationList {
	t.Helper()
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	return crl
}

func newSerial(value int64) *big.Int { return big.NewInt(value) }

func timeForRenewedCLITest() time.Time { return time.Unix(1, 0) }
