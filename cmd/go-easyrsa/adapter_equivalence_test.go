package main

import (
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestCLIAndDirectPKIProduceEquivalentRenewedLifecycle(t *testing.T) {
	t.Setenv("EASYRSA_RAND_SN", "no")
	directDir := filepath.Join(t.TempDir(), "direct")
	cliDir := filepath.Join(t.TempDir(), "cli")

	direct, err := pki.OpenWithFS(directDir, pki.Config{
		NoPass:           true,
		SequentialSerial: true,
		KeyAlgo:          pki.AlgoRSA,
		KeySize:          1024,
	})
	require.NoError(t, err)
	require.NoError(t, direct.InitPKI(pki.InitPKIOptions{}))
	_, err = direct.BuildCA(pki.WithCN("Easy-RSA CA"))
	require.NoError(t, err)
	directOld, err := direct.BuildClientFull("alice")
	require.NoError(t, err)
	directOldSerial, err := directOld.Serial()
	require.NoError(t, err)
	directCurrent, err := direct.Renew("alice")
	require.NoError(t, err)
	directCurrentSerial, err := directCurrent.Serial()
	require.NoError(t, err)
	_, err = direct.GenCRL()
	require.NoError(t, err)
	directCRLBeforePEM, err := os.ReadFile(filepath.Join(directDir, "crl.pem"))
	require.NoError(t, err)
	directCSRBefore, err := os.ReadFile(filepath.Join(directDir, "reqs", "alice.req"))
	require.NoError(t, err)
	writeRenewedCLIArtifacts(t, directDir, "alice")

	for _, arguments := range [][]string{
		{"--pki-dir", cliDir, "init-pki"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-ca"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-client-full", "alice"},
		{"--pki-dir", cliDir, "renew", "alice"},
	} {
		output, err := runCLI(t, arguments...)
		require.NoError(t, err, "%v: %s", arguments, output)
	}
	output, err := runCLI(t, "--pki-dir", cliDir, "gen-crl")
	require.NoError(t, err, output)
	cliCRLBeforePEM, err := os.ReadFile(filepath.Join(cliDir, "crl.pem"))
	require.NoError(t, err)
	cliCSRBefore, err := os.ReadFile(filepath.Join(cliDir, "reqs", "alice.req"))
	require.NoError(t, err)
	writeRenewedCLIArtifacts(t, cliDir, "alice")
	cliPKI, err := pki.OpenWithFS(cliDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	cliCurrent, err := cliPKI.ShowCert("alice")
	require.NoError(t, err)
	cliCurrentSerial, err := cliCurrent.Serial()
	require.NoError(t, err)
	cliReport, err := cliPKI.ShowRenewed()
	require.NoError(t, err)
	directReport, err := direct.ShowRenewed()
	require.NoError(t, err)
	require.Len(t, directReport, 1)
	require.Len(t, cliReport, 1)
	require.Equal(t, directReport[0].Name, cliReport[0].Name)
	require.Equal(t, directReport[0].CommonName, cliReport[0].CommonName)
	require.Equal(t, directReport[0].Status, cliReport[0].Status)
	require.Equal(t, directReport[0].RequiresRewind, cliReport[0].RequiresRewind)
	require.Zero(t, directReport[0].Serial.Cmp(cliReport[0].Serial))
	output, err = runCLI(t, "--pki-dir", cliDir, "show-renew", "alice")
	require.NoError(t, err, output)
	require.Contains(t, output, storage.HexSerial(cliReport[0].Serial))

	directBefore, err := direct.ExportSnapshot()
	require.NoError(t, err)
	cliBefore, err := cliPKI.ExportSnapshot()
	require.NoError(t, err)
	require.Equal(t, snapshotShape(directBefore), snapshotShape(cliBefore))
	require.NoError(t, direct.RevokeRenewed("alice", cert.ReasonCertificateHold))
	output, err = runCLI(t, "--pki-dir", cliDir, "revoke-renewed", "alice", "certificateHold")
	require.NoError(t, err, output)

	directAfterCurrent, err := direct.ShowCert("alice")
	require.NoError(t, err)
	cliAfterCurrent, err := cliPKI.ShowCert("alice")
	require.NoError(t, err)
	require.Equal(t, directCurrent.CertPEM, directAfterCurrent.CertPEM)
	require.Equal(t, directCurrent.KeyPEM, directAfterCurrent.KeyPEM)
	require.Equal(t, cliCurrent.CertPEM, cliAfterCurrent.CertPEM)
	require.Equal(t, cliCurrent.KeyPEM, cliAfterCurrent.KeyPEM)
	directCSRAfter, err := os.ReadFile(filepath.Join(directDir, "reqs", "alice.req"))
	require.NoError(t, err)
	cliCSRAfter, err := os.ReadFile(filepath.Join(cliDir, "reqs", "alice.req"))
	require.NoError(t, err)
	require.Equal(t, directCSRBefore, directCSRAfter)
	require.Equal(t, cliCSRBefore, cliCSRAfter)
	directCRLAfterPEM, err := os.ReadFile(filepath.Join(directDir, "crl.pem"))
	require.NoError(t, err)
	cliCRLAfterPEM, err := os.ReadFile(filepath.Join(cliDir, "crl.pem"))
	require.NoError(t, err)
	require.Equal(t, directCRLBeforePEM, directCRLAfterPEM)
	require.Equal(t, cliCRLBeforePEM, cliCRLAfterPEM)
	for _, directory := range []string{directDir, cliDir} {
		for _, artifact := range renewedCLIArtifactPaths("alice") {
			require.NoFileExists(t, filepath.Join(directory, filepath.FromSlash(artifact)))
		}
	}
	directOldEntry, err := direct.CheckSerial(directOldSerial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusRevoked, directOldEntry.Status)
	require.Equal(t, cert.ReasonCertificateHold, directOldEntry.RevocationReason)
	directCurrentEntry, err := direct.CheckSerial(directCurrentSerial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusValid, directCurrentEntry.Status)
	cliOldEntry, err := cliPKI.CheckSerial(cliReport[0].Serial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusRevoked, cliOldEntry.Status)
	require.Equal(t, cert.ReasonCertificateHold, cliOldEntry.RevocationReason)
	cliCurrentEntry, err := cliPKI.CheckSerial(cliCurrentSerial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusValid, cliCurrentEntry.Status)

	directAfter, err := direct.ExportSnapshot()
	require.NoError(t, err)
	cliAfter, err := cliPKI.ExportSnapshot()
	require.NoError(t, err)
	require.Equal(t, snapshotShape(directAfter), snapshotShape(cliAfter))
	_, err = direct.GenCRL()
	require.NoError(t, err)
	_, err = cliPKI.GenCRL()
	require.NoError(t, err)
	directCRL, err := direct.ShowCRL()
	require.NoError(t, err)
	cliCRL, err := cliPKI.ShowCRL()
	require.NoError(t, err)
	require.Len(t, directCRL.RevokedCertificateEntries, 1)
	require.Len(t, cliCRL.RevokedCertificateEntries, 1)
	require.Equal(t, int(cert.ReasonCertificateHold), directCRL.RevokedCertificateEntries[0].ReasonCode)
	require.Equal(t, int(cert.ReasonCertificateHold), cliCRL.RevokedCertificateEntries[0].ReasonCode)
}

func TestCLIAndDirectPKIProduceEquivalentHistoricalRenewalSource(t *testing.T) {
	t.Setenv("EASYRSA_RAND_SN", "no")
	directDir := filepath.Join(t.TempDir(), "direct")
	cliDir := filepath.Join(t.TempDir(), "cli")
	direct, err := pki.OpenWithFS(directDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)
	require.NoError(t, direct.InitPKI(pki.InitPKIOptions{}))
	_, err = direct.BuildCA(pki.WithCN("Easy-RSA CA"))
	require.NoError(t, err)
	_, err = direct.BuildClientFull("alice")
	require.NoError(t, err)
	_, err = direct.Renew("alice")
	require.NoError(t, err)
	for _, arguments := range [][]string{
		{"--pki-dir", cliDir, "init-pki"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-ca"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-client-full", "alice"},
		{"--pki-dir", cliDir, "renew", "alice"},
	} {
		output, err := runCLI(t, arguments...)
		require.NoError(t, err, "%v: %s", arguments, output)
	}
	directSerial := moveNamedRenewalToSerialArchive(t, directDir, "alice")
	cliSerial := moveNamedRenewalToSerialArchive(t, cliDir, "alice")
	require.Zero(t, directSerial.Cmp(cliSerial))

	cliPKI, err := pki.OpenWithFS(cliDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	directReport, err := direct.ShowRenewed()
	require.NoError(t, err)
	cliReport, err := cliPKI.ShowRenewed()
	require.NoError(t, err)
	require.Len(t, directReport, 1)
	require.Len(t, cliReport, 1)
	require.True(t, directReport[0].RequiresRewind)
	require.True(t, cliReport[0].RequiresRewind)
	directSnapshot, err := direct.ExportSnapshot()
	require.NoError(t, err)
	cliSnapshot, err := cliPKI.ExportSnapshot()
	require.NoError(t, err)
	require.Equal(t, snapshotShape(directSnapshot), snapshotShape(cliSnapshot))
	output, err := runCLI(t, "--pki-dir", cliDir, "show-renew", "alice")
	require.NoError(t, err, output)
	require.Contains(t, output, "*** V | Serial: "+storage.HexSerial(cliSerial))
}

func TestCLIAndDirectPKIProduceEquivalentLifecycleStateShape(t *testing.T) {
	t.Setenv("EASYRSA_RAND_SN", "no")
	directDir := filepath.Join(t.TempDir(), "direct")
	cliDir := filepath.Join(t.TempDir(), "cli")

	direct, err := pki.OpenWithFS(directDir, pki.Config{
		NoPass:           true,
		SequentialSerial: true,
		KeyAlgo:          pki.AlgoRSA,
		KeySize:          1024,
	})
	require.NoError(t, err)
	require.NoError(t, direct.InitPKI(pki.InitPKIOptions{}))
	_, err = direct.BuildCA(pki.WithCN("Easy-RSA CA"))
	require.NoError(t, err)
	_, err = direct.BuildClientFull("alice")
	require.NoError(t, err)
	_, err = direct.Renew("alice")
	require.NoError(t, err)
	_, err = direct.BuildClientFull("bob")
	require.NoError(t, err)
	require.NoError(t, direct.RevokeIssued("bob", cert.ReasonUnspecified))
	_, err = direct.GenCRL()
	require.NoError(t, err)

	commands := [][]string{
		{"--pki-dir", cliDir, "init-pki"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-ca"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-client-full", "alice"},
		{"--pki-dir", cliDir, "renew", "alice"},
		{"--pki-dir", cliDir, "--nopass", "--keysize=1024", "build-client-full", "bob"},
		{"--pki-dir", cliDir, "revoke-issued", "bob"},
		{"--pki-dir", cliDir, "gen-crl"},
	}
	for _, arguments := range commands {
		output, err := runCLI(t, arguments...)
		require.NoError(t, err, "%v: %s", arguments, output)
	}
	cliPKI, err := pki.OpenWithFS(cliDir, pki.Config{NoPass: true, SequentialSerial: true, KeyAlgo: pki.AlgoRSA, KeySize: 1024})
	require.NoError(t, err)

	directSnapshot, err := direct.ExportSnapshot()
	require.NoError(t, err)
	cliSnapshot, err := cliPKI.ExportSnapshot()
	require.NoError(t, err)
	require.Equal(t, snapshotShape(directSnapshot), snapshotShape(cliSnapshot))
	directCRL, err := direct.ShowCRL()
	require.NoError(t, err)
	cliCRL, err := cliPKI.ShowCRL()
	require.NoError(t, err)
	require.Len(t, cliCRL.RevokedCertificateEntries, len(directCRL.RevokedCertificateEntries))
	require.FileExists(t, filepath.Join(cliDir, "crl.pem"))
	require.FileExists(t, filepath.Join(cliDir, "crl.der"))
}

func moveNamedRenewalToSerialArchive(t *testing.T, pkiDir, name string) *big.Int {
	t.Helper()
	source := filepath.Join(pkiDir, "renewed", "issued", name+".crt")
	certificatePEM, err := os.ReadFile(source)
	require.NoError(t, err)
	serial, err := (&cert.Pair{Name: name, CertPEM: certificatePEM}).Serial()
	require.NoError(t, err)
	destinationDir := filepath.Join(pkiDir, "renewed", "certs_by_serial")
	require.NoError(t, os.MkdirAll(destinationDir, 0o755))
	require.NoError(t, os.Rename(source, filepath.Join(destinationDir, storage.HexSerial(serial)+".crt")))
	return serial
}

type comparableSnapshotShape struct {
	Statuses      []storage.CertStatus
	Current       []string
	Expired       []string
	Renewed       []string
	RenewalSource []string
	Revoked       []string
}

func snapshotShape(snapshot *pki.Snapshot) comparableSnapshotShape {
	shape := comparableSnapshotShape{}
	for _, entry := range snapshot.Index {
		shape.Statuses = append(shape.Statuses, entry.Status)
	}
	for _, current := range snapshot.Current {
		shape.Current = append(shape.Current, current.Name)
	}
	for _, record := range snapshot.Lifecycle.Expired {
		shape.Expired = append(shape.Expired, record.Name)
	}
	for _, record := range snapshot.Lifecycle.Renewed {
		shape.Renewed = append(shape.Renewed, record.Name)
		shape.RenewalSource = append(shape.RenewalSource, record.Name+":"+string(record.RenewalSource))
	}
	for _, record := range snapshot.Lifecycle.Revoked {
		shape.Revoked = append(shape.Revoked, record.Name)
	}
	sort.Slice(shape.Statuses, func(i, j int) bool { return shape.Statuses[i] < shape.Statuses[j] })
	sort.Strings(shape.Current)
	sort.Strings(shape.Expired)
	sort.Strings(shape.Renewed)
	sort.Strings(shape.RenewalSource)
	sort.Strings(shape.Revoked)
	return shape
}
