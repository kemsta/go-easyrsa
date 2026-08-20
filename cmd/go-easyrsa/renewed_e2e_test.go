//go:build e2e

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

var renewedReportPattern = regexp.MustCompile(`(?m)^(\*\*\* )?([VE]) \| Serial: ([0-9A-Fa-f]+) \| Expires: (.+?) \| CN: (.+?)\r?$`)

type renewedReportRow struct {
	Status         string
	Serial         string
	ExpiresAt      time.Time
	CommonName     string
	RequiresRewind bool
}

func TestE2E_RenewedLifecycleParity(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, []string{"EASYRSA_NO_PASS=1"}, nil)
	runners := []struct {
		name               string
		runner             binaryRunner
		oldCertificate     []byte
		oldSerial          string
		currentCertificate []byte
		currentKey         []byte
		currentRequest     []byte
	}{
		{name: "easy-rsa", runner: easyRunner},
		{name: "go-easyrsa", runner: goRunner},
	}
	for i := range runners {
		for _, args := range [][]string{
			{"init-pki"},
			{"build-ca"},
			{"build-client-full", "alice"},
		} {
			output, err := runners[i].runner.run(args...)
			require.NoError(t, err, "%s %v\n%s", runners[i].name, args, output)
		}
		runners[i].oldCertificate = runners[i].runner.readArtifact(t, "issued", "alice.crt")
		old := parseCertificatePEM(t, runners[i].oldCertificate)
		runners[i].oldSerial = storage.HexSerial(old.SerialNumber)
		output, err := runners[i].runner.run("renew", "alice")
		require.NoError(t, err, "%s renew\n%s", runners[i].name, output)
		runners[i].currentCertificate = runners[i].runner.readArtifact(t, "issued", "alice.crt")
		runners[i].currentKey = runners[i].runner.readArtifact(t, "private", "alice.key")
		runners[i].currentRequest = runners[i].runner.readArtifact(t, "reqs", "alice.req")
	}

	easyRows := runRenewedReport(t, easyRunner, "show-renew")
	goRows := runRenewedReport(t, goRunner, "show-renew")
	compareRenewedReports(t, easyRows, goRows)
	require.Len(t, easyRows, 1)
	require.Equal(t, runners[0].oldSerial, easyRows[0].Serial)
	require.Equal(t, runners[1].oldSerial, goRows[0].Serial)
	easyTargetRows := runRenewedReport(t, easyRunner, "show-renew", "alice")
	goTargetRows := runRenewedReport(t, goRunner, "show-renew", "alice")
	compareRenewedReports(t, easyTargetRows, goTargetRows)
	require.Equal(t, easyRows[0].Serial, easyTargetRows[0].Serial)
	require.Equal(t, goRows[0].Serial, goTargetRows[0].Serial)
	require.Empty(t, runRenewedReport(t, easyRunner, "show-renew", "missing"))
	require.Empty(t, runRenewedReport(t, goRunner, "show-renew", "missing"))

	for i := range runners {
		_, err := os.Stat(filepath.Join(runners[i].runner.pkiDir, "crl.pem"))
		require.ErrorIs(t, err, os.ErrNotExist)
		output, err := runners[i].runner.run("revoke-renewed", "alice", "certificateHold")
		require.NoError(t, err, "%s revoke-renewed\n%s", runners[i].name, output)
		require.Equal(t, runners[i].currentCertificate, runners[i].runner.readArtifact(t, "issued", "alice.crt"))
		require.Equal(t, runners[i].currentKey, runners[i].runner.readArtifact(t, "private", "alice.key"))
		require.Equal(t, runners[i].currentRequest, runners[i].runner.readArtifact(t, "reqs", "alice.req"))
		require.NoFileExists(t, filepath.Join(runners[i].runner.pkiDir, "renewed", "issued", "alice.crt"))
		require.Equal(t, runners[i].oldCertificate, runners[i].runner.readArtifact(t, "revoked", "certs_by_serial", runners[i].oldSerial+".crt"))
		_, err = os.Stat(filepath.Join(runners[i].runner.pkiDir, "crl.pem"))
		require.ErrorIs(t, err, os.ErrNotExist)
		require.Empty(t, runRenewedReport(t, runners[i].runner, "show-renew"))
	}
	compareStates(t, loadState(t, easyDir), loadState(t, goDir), stateComparisonOptions{})

	for i := range runners {
		output, err := runners[i].runner.run("gen-crl")
		require.NoError(t, err, "%s gen-crl\n%s", runners[i].name, output)
		crl := parseCRL(t, runners[i].runner.readArtifact(t, "crl.pem"))
		require.Len(t, crl.RevokedCertificateEntries, 1)
		require.Equal(t, int(cert.ReasonCertificateHold), crl.RevokedCertificateEntries[0].ReasonCode)
		output, err = runners[i].runner.run("renew", "alice")
		require.NoError(t, err, "%s second renew\n%s", runners[i].name, output)
	}
	compareStates(t, loadState(t, easyDir), loadState(t, goDir), stateComparisonOptions{normalizeSupersededRenewal: true})
}

func TestE2E_ShowRenewedHistoricalArchiveParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, []string{"EASYRSA_NO_PASS=1"}, nil)
	var archiveSerials []string
	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		for _, args := range [][]string{{"init-pki"}, {"build-ca"}, {"build-client-full", "alice"}, {"renew", "alice"}} {
			output, err := runner.run(args...)
			require.NoError(t, err, "%v\n%s", args, output)
		}
		certificatePEM := runner.readArtifact(t, "renewed", "issued", "alice.crt")
		certificate := parseCertificatePEM(t, certificatePEM)
		historicalDir := filepath.Join(runner.pkiDir, "renewed", "certs_by_serial")
		require.NoError(t, os.MkdirAll(historicalDir, 0o755))
		serial := storage.HexSerial(certificate.SerialNumber)
		require.NoError(t, os.Rename(
			filepath.Join(runner.pkiDir, "renewed", "issued", "alice.crt"),
			filepath.Join(historicalDir, serial+".crt"),
		))
		archiveSerials = append(archiveSerials, serial)
	}

	easyRows := runRenewedReport(t, easyRunner, "show-renew")
	goRows := runRenewedReport(t, goRunner, "show-renew")
	compareRenewedReports(t, easyRows, goRows)
	require.Len(t, easyRows, 1)
	require.Equal(t, archiveSerials[0], easyRows[0].Serial)
	require.Equal(t, archiveSerials[1], goRows[0].Serial)
	require.True(t, easyRows[0].RequiresRewind)
	require.True(t, goRows[0].RequiresRewind)
	easyTargetRows := runRenewedReport(t, easyRunner, "show-renew", "alice")
	goTargetRows := runRenewedReport(t, goRunner, "show-renew", "alice")
	compareRenewedReports(t, easyTargetRows, goTargetRows)
	require.Equal(t, easyRows[0].Serial, easyTargetRows[0].Serial)
	require.Equal(t, goRows[0].Serial, goTargetRows[0].Serial)
}

func TestE2E_ShowRenewedNameCNDifferenceParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, []string{"EASYRSA_NO_PASS=1"}, []string{
		"EASYRSA_DN=org",
		"EASYRSA_REQ_CN=different-cn",
		"EASYRSA_REQ_ORG=Acme",
	})
	for _, runner := range []binaryRunner{easyRunner, goRunner} {
		for _, args := range [][]string{{"init-pki"}, {"build-ca"}, {"build-client-full", "storage-name"}, {"renew", "storage-name"}} {
			output, err := runner.run(args...)
			require.NoError(t, err, "%v\n%s", args, output)
		}
		require.Empty(t, runRenewedReport(t, runner, "show-renew"))
		require.Empty(t, runRenewedReport(t, runner, "show-renew", "storage-name"))
		require.Empty(t, runRenewedReport(t, runner, "show-renew", "different-cn"))
	}
}

func runRenewedReport(t *testing.T, runner binaryRunner, args ...string) []renewedReportRow {
	t.Helper()
	output, err := runner.run(args...)
	require.NoError(t, err, "%v\n%s", args, output)
	return parseRenewedReport(t, output)
}

func parseRenewedReport(t *testing.T, output string) []renewedReportRow {
	t.Helper()
	matches := renewedReportPattern.FindAllStringSubmatch(output, -1)
	rows := make([]renewedReportRow, 0, len(matches))
	for _, match := range matches {
		expiresAt, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(match[4]))
		require.NoError(t, err, match[0])
		rows = append(rows, renewedReportRow{
			Status:         match[2],
			Serial:         strings.ToUpper(match[3]),
			ExpiresAt:      expiresAt,
			CommonName:     strings.TrimSpace(match[5]),
			RequiresRewind: match[1] != "",
		})
	}
	return rows
}

func compareRenewedReports(t *testing.T, expected, actual []renewedReportRow) {
	t.Helper()
	require.Len(t, actual, len(expected))
	for i := range expected {
		require.Equal(t, expected[i].Status, actual[i].Status)
		require.NotEmpty(t, expected[i].Serial)
		require.NotEmpty(t, actual[i].Serial)
		require.Equal(t, expected[i].CommonName, actual[i].CommonName)
		require.Equal(t, expected[i].RequiresRewind, actual[i].RequiresRewind)
		require.WithinDuration(t, expected[i].ExpiresAt, actual[i].ExpiresAt, 2*time.Minute)
	}
}
