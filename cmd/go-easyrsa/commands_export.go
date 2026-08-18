package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/spf13/cobra"
	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	pkicrypto "github.com/kemsta/go-easyrsa/v2/crypto"
	"github.com/kemsta/go-easyrsa/v2/pki"
)

func newExportP12Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p12 <name> [nopass|noca|nokey|nofn|legacy]",
		Short: "Export a PKCS#12 bundle",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmdOpts, err := parseCommandOpts(args[1:], "nopass", "noca", "nokey", "nofn", "legacy")
			if err != nil {
				return err
			}
			pk, cfg, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			data, err := exportP12(pk, cfg, opts, args[0], cmdOpts)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func newExportP7Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p7 <name> [noca]",
		Short: "Export a PKCS#7 bundle",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmdOpts, err := parseCommandOpts(args[1:], "noca")
			if err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			data, err := exportP7(pk, args[0], cmdOpts)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func newExportP8Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p8 <name> [nopass]",
		Short: "Export a PKCS#8 private key",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmdOpts, err := parseCommandOpts(args[1:], "nopass")
			if err != nil {
				return err
			}
			pk, cfg, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			password, err := outputPassword(opts, cmdOpts)
			if err != nil {
				return err
			}
			cfg.KeyPassphrase = effectivePassIn(opts, cfg)
			data, err := pk.ExportP8(args[0], password)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func newExportP1Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p1 <name> [nopass]",
		Short: "Export a PKCS#1 private key",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmdOpts, err := parseCommandOpts(args[1:], "nopass")
			if err != nil {
				return err
			}
			pk, cfg, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			data, err := exportP1(pk, cfg, opts, args[0], cmdOpts)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func exportP12(pk *pki.PKI, cfg pki.Config, opts *cliOptions, name string, cmdOpts map[string]bool) ([]byte, error) {
	if opts.useFN != "" || cmdOpts["nofn"] {
		return nil, errors.New("go-easyrsa: PKCS#12 friendlyName customization is not implemented yet")
	}
	pair, err := pk.ShowCert(name)
	if err != nil {
		return nil, err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return nil, err
	}

	password, err := outputPassword(opts, cmdOpts)
	if err != nil {
		return nil, err
	}
	encoder := gopkcs12.Modern
	if cmdOpts["legacy"] {
		encoder = gopkcs12.Legacy
	}
	if password == "" && !cmdOpts["legacy"] {
		encoder = gopkcs12.Passwordless
	}

	var caCerts []*x509.Certificate
	if !cmdOpts["noca"] {
		caPair, err := pk.ShowCA()
		if err != nil {
			return nil, err
		}
		caCert, err := caPair.Certificate()
		if err != nil {
			return nil, err
		}
		caCerts = append(caCerts, caCert)
	}

	if cmdOpts["nokey"] {
		certs := []*x509.Certificate{certificate}
		certs = append(certs, caCerts...)
		return encoder.EncodeTrustStore(certs, password)
	}

	privateKey, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, effectivePassIn(opts, cfg))
	if err != nil {
		return nil, err
	}
	return encoder.Encode(privateKey, certificate, caCerts, password)
}

func exportP7(pk *pki.PKI, name string, cmdOpts map[string]bool) ([]byte, error) {
	pair, err := pk.ShowCert(name)
	if err != nil {
		return nil, err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return nil, err
	}
	sd, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return nil, err
	}
	sd.AddCertificate(certificate)
	if !cmdOpts["noca"] {
		caPair, err := pk.ShowCA()
		if err != nil {
			return nil, err
		}
		caCert, err := caPair.Certificate()
		if err != nil {
			return nil, err
		}
		sd.AddCertificate(caCert)
	}
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der}), nil
}

func exportP1(pk *pki.PKI, cfg pki.Config, opts *cliOptions, name string, cmdOpts map[string]bool) ([]byte, error) {
	pair, err := pk.ShowCert(name)
	if err != nil {
		return nil, err
	}
	privateKey, err := pkicrypto.UnmarshalPrivateKey(pair.KeyPEM, effectivePassIn(opts, cfg))
	if err != nil {
		return nil, err
	}
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: ExportP1 requires an RSA private key")
	}
	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	password, err := outputPassword(opts, cmdOpts)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte(password), x509.PEMCipherAES256) //nolint:staticcheck // compatibility with legacy PEM encryption
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

func effectivePassIn(opts *cliOptions, cfg pki.Config) string {
	if opts.passIn != "" {
		return parsePassEnv(opts.passIn)
	}
	if cfg.KeyPassphrase != "" {
		return cfg.KeyPassphrase
	}
	return cfg.CAPassphrase
}

func outputPassword(opts *cliOptions, cmdOpts map[string]bool) (string, error) {
	if opts.noPass || cmdOpts["nopass"] {
		return "", nil
	}
	if opts.passOut == "" {
		return "", errors.New("go-easyrsa: --passout or nopass is required for output key protection")
	}
	password := parsePassEnv(opts.passOut)
	if password == "" {
		return "", errors.New("go-easyrsa: output passphrase must not be empty; use nopass explicitly")
	}
	return password, nil
}
