package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
)

const legacyValidityDays = 99 * 365

var legacyNsCertTypeOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var keyDir string

	cmd := &cobra.Command{
		Use:   "go-easyrsa-legacy-cli",
		Short: "Legacy-compatible v1 CLI on top of the current go-easyrsa PKI",
	}

	cmd.PersistentFlags().StringVarP(&keyDir, "key-dir", "k", "keys", "PKI directory")
	cmd.AddCommand(
		newBuildCACmd(&keyDir),
		newBuildServerKeyCmd(&keyDir),
		newBuildKeyCmd(&keyDir),
		newRevokeFullCmd(&keyDir),
	)
	return cmd
}

func newBuildCACmd(keyDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "build-ca",
		Short: "build ca cert/key",
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, err := openPKI(*keyDir)
			if err != nil {
				return err
			}
			_, err = pk.BuildCA(legacyBaseOptions()...)
			return err
		},
	}
}

func newBuildServerKeyCmd(keyDir *string) *cobra.Command {
	var dnsNames []string
	var ips []net.IP

	cmd := &cobra.Command{
		Use:   "build-server-key [cn]",
		Short: "build server cert/key",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, err := openPKI(*keyDir)
			if err != nil {
				return err
			}
			_, err = pk.BuildServerFull(args[0], legacyServerOptions(dnsNames, ips)...)
			return err
		},
	}

	cmd.Flags().StringArrayVarP(&dnsNames, "dns", "n", nil, "server dns names")
	cmd.Flags().IPSliceVarP(&ips, "ip", "i", nil, "server ip addresses")
	return cmd
}

func newBuildKeyCmd(keyDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "build-key [cn]",
		Short: "build client cert/key",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, err := openPKI(*keyDir)
			if err != nil {
				return err
			}
			_, err = pk.BuildClientFull(args[0], legacyClientOptions()...)
			return err
		},
	}
}

func newRevokeFullCmd(keyDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke-full [cn]",
		Short: "revoke cert",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, err := openPKI(*keyDir)
			if err != nil {
				return err
			}
			return pk.Revoke(args[0], cert.ReasonUnspecified)
		},
	}
}

func openPKI(keyDir string) (*pki.PKI, error) {
	return pki.NewWithFS(keyDir, legacyConfig())
}

func legacyConfig() pki.Config {
	return pki.Config{
		NoPass:      true,
		KeyAlgo:     pki.AlgoRSA,
		KeySize:     2048,
		DefaultDays: legacyValidityDays,
		CADays:      legacyValidityDays,
		CRLDays:     legacyValidityDays,
	}
}

func legacyBaseOptions() []pki.Option {
	return []pki.Option{pki.WithNotBefore(time.Now().Add(-10 * time.Minute).UTC())}
}

func legacyServerOptions(dnsNames []string, ips []net.IP) []pki.Option {
	opts := legacyBaseOptions()
	if len(dnsNames) > 0 {
		opts = append(opts, pki.WithDNSNames(dnsNames...))
	}
	if len(ips) > 0 {
		opts = append(opts, pki.WithIPAddresses(ips...))
	}
	return append(opts, pki.WithCertModifier(applyLegacyServerProfile))
}

func legacyClientOptions() []pki.Option {
	return append(legacyBaseOptions(), pki.WithCertModifier(applyLegacyClientProfile))
}

func applyLegacyServerProfile(c *x509.Certificate) {
	c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	c.ExtraExtensions = putLegacyNsCertType(c.ExtraExtensions, 0x40)
}

func applyLegacyClientProfile(c *x509.Certificate) {
	c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	c.ExtraExtensions = putLegacyNsCertType(c.ExtraExtensions, 0x80)
}

func putLegacyNsCertType(exts []pkix.Extension, b byte) []pkix.Extension {
	filtered := exts[:0]
	for _, ext := range exts {
		if !ext.Id.Equal(legacyNsCertTypeOID) {
			filtered = append(filtered, ext)
		}
	}
	val, err := asn1.Marshal(asn1.BitString{Bytes: []byte{b}, BitLength: 2})
	if err != nil {
		return filtered
	}
	return append(filtered, pkix.Extension{Id: legacyNsCertTypeOID, Value: val})
}
