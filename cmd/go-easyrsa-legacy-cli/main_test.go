package main

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kemsta/go-easyrsa/v2/cert"
)

func TestCLI_BuildCA(t *testing.T) {
	dir := t.TempDir()

	out, err := runCLI(t, "--key-dir", dir, "build-ca")
	require.NoError(t, err, out)

	pk := openFS(t, dir)
	pair, err := pk.ShowCA()
	require.NoError(t, err)
	require.True(t, pair.HasKey())
	_, err = pair.PrivateKey()
	require.NoError(t, err)

	ca, err := pair.Certificate()
	require.NoError(t, err)
	require.True(t, ca.IsCA)
	requireBackdatedLegacyWindow(t, ca)
}

func TestCLI_BuildKey(t *testing.T) {
	dir := t.TempDir()

	_, err := runCLI(t, "-k", dir, "build-ca")
	require.NoError(t, err)
	out, err := runCLI(t, "-k", dir, "build-key", "client1")
	require.NoError(t, err, out)

	pk := openFS(t, dir)
	pair, err := pk.ShowCert("client1")
	require.NoError(t, err)
	require.True(t, pair.HasKey())
	_, err = pair.PrivateKey()
	require.NoError(t, err)

	certType, err := pair.CertType()
	require.NoError(t, err)
	require.Equal(t, cert.CertTypeClient, certType)

	c, err := pair.Certificate()
	require.NoError(t, err)
	requireBackdatedLegacyWindow(t, c)
	require.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement, c.KeyUsage)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, c.ExtKeyUsage)
	require.True(t, hasNsCertType(t, c, 0x80))
}

func TestCLI_BuildServerKey(t *testing.T) {
	dir := t.TempDir()

	_, err := runCLI(t, "-k", dir, "build-ca")
	require.NoError(t, err)
	out, err := runCLI(t,
		"-k", dir,
		"build-server-key", "server1",
		"--dns", "vpn.example.test",
		"--ip", "127.0.0.1",
	)
	require.NoError(t, err, out)

	pk := openFS(t, dir)
	pair, err := pk.ShowCert("server1")
	require.NoError(t, err)

	certType, err := pair.CertType()
	require.NoError(t, err)
	require.Equal(t, cert.CertTypeServer, certType)

	c, err := pair.Certificate()
	require.NoError(t, err)
	requireBackdatedLegacyWindow(t, c)
	require.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement|x509.KeyUsageKeyEncipherment, c.KeyUsage)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, c.ExtKeyUsage)
	require.Equal(t, []string{"vpn.example.test"}, c.DNSNames)
	require.Len(t, c.IPAddresses, 1)
	require.Equal(t, "127.0.0.1", c.IPAddresses[0].String())
	require.True(t, hasNsCertType(t, c, 0x40))
}

func TestCLI_RevokeFull(t *testing.T) {
	dir := t.TempDir()

	_, err := runCLI(t, "-k", dir, "build-ca")
	require.NoError(t, err)
	_, err = runCLI(t, "-k", dir, "build-key", "client1")
	require.NoError(t, err)
	out, err := runCLI(t, "-k", dir, "revoke-full", "client1")
	require.NoError(t, err, out)

	pk := openFS(t, dir)
	pair, err := pk.ShowCert("client1")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	revoked, err := pk.IsRevoked(serial)
	require.NoError(t, err)
	require.True(t, revoked)

	crl, err := pk.ShowCRL()
	require.NoError(t, err)
	require.Len(t, crl.RevokedCertificateEntries, 1)
}
