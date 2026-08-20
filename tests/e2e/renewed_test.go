//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/internal/testutil"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestEasyRSARenewalContinuedByPKI(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")
	er.Run("renew", "client1")

	pk, err := pki.OpenWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	renewed, err := pk.ShowRenewed()
	require.NoError(t, err)
	require.Len(t, renewed, 1)
	require.Equal(t, "client1", renewed[0].Name)
	require.False(t, renewed[0].RequiresRewind)
	currentCertificate := mustReadRenewalFile(t, pkiDir, "issued", "client1.crt")
	currentKey := mustReadRenewalFile(t, pkiDir, "private", "client1.key")
	currentRequest := mustReadRenewalFile(t, pkiDir, "reqs", "client1.req")

	require.NoError(t, pk.RevokeRenewed("client1", cert.ReasonCertificateHold))
	require.Equal(t, currentCertificate, mustReadRenewalFile(t, pkiDir, "issued", "client1.crt"))
	require.Equal(t, currentKey, mustReadRenewalFile(t, pkiDir, "private", "client1.key"))
	require.Equal(t, currentRequest, mustReadRenewalFile(t, pkiDir, "reqs", "client1.req"))
	_, err = os.Stat(filepath.Join(pkiDir, "crl.pem"))
	require.ErrorIs(t, err, os.ErrNotExist)

	er.Run("gen-crl")
	crl, err := pk.ShowCRL()
	require.NoError(t, err)
	require.Len(t, crl.RevokedCertificateEntries, 1)
	require.Equal(t, int(cert.ReasonCertificateHold), crl.RevokedCertificateEntries[0].ReasonCode)
	er.Run("renew", "client1")
}

func TestPKIRenewalContinuedByEasyRSA(t *testing.T) {
	pkiDir := t.TempDir()
	er := testutil.NewRunner(t, pkiDir)
	er.Run("init-pki")
	er.Run("build-ca", "nopass")
	er.Run("build-client-full", "client1", "nopass")

	pk, err := pki.OpenWithFS(pkiDir, pki.Config{NoPass: true})
	require.NoError(t, err)
	old, err := pk.ShowCert("client1")
	require.NoError(t, err)
	oldSerial, err := old.Serial()
	require.NoError(t, err)
	_, err = pk.Renew("client1")
	require.NoError(t, err)
	currentCertificate := mustReadRenewalFile(t, pkiDir, "issued", "client1.crt")
	currentKey := mustReadRenewalFile(t, pkiDir, "private", "client1.key")
	currentRequest := mustReadRenewalFile(t, pkiDir, "reqs", "client1.req")

	output := er.Run("show-renew", "client1")
	require.Contains(t, strings.ToLower(output), "client1")
	er.Run("revoke-renewed", "client1", "certificateHold")
	require.Equal(t, currentCertificate, mustReadRenewalFile(t, pkiDir, "issued", "client1.crt"))
	require.Equal(t, currentKey, mustReadRenewalFile(t, pkiDir, "private", "client1.key"))
	require.Equal(t, currentRequest, mustReadRenewalFile(t, pkiDir, "reqs", "client1.req"))
	entry, err := pk.CheckSerial(oldSerial)
	require.NoError(t, err)
	require.Equal(t, storage.StatusRevoked, entry.Status)
	require.Equal(t, cert.ReasonCertificateHold, entry.RevocationReason)
	_, err = os.Stat(filepath.Join(pkiDir, "crl.pem"))
	require.ErrorIs(t, err, os.ErrNotExist)

	er.Run("gen-crl")
	crl, err := pk.ShowCRL()
	require.NoError(t, err)
	require.Len(t, crl.RevokedCertificateEntries, 1)
	require.Equal(t, int(cert.ReasonCertificateHold), crl.RevokedCertificateEntries[0].ReasonCode)
}

func mustReadRenewalFile(t *testing.T, pkiDir string, path ...string) []byte {
	t.Helper()
	parts := append([]string{pkiDir}, path...)
	data, err := os.ReadFile(filepath.Join(parts...))
	require.NoError(t, err)
	return data
}
