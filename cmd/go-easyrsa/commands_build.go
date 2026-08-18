package main

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
)

func newInitPKICmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "init-pki [algo] [curve]",
		Short: "Initialize a PKI directory",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildConfig(opts)
			if err != nil {
				return err
			}
			if len(args) > 0 {
				algo, ok := parseEasyRSAAlgo(args[0])
				if !ok {
					return fmt.Errorf("unknown init-pki algorithm %q", args[0])
				}
				cfg.KeyAlgo = algo
				if algo == pki.AlgoECDSA && cfg.Curve == nil {
					cfg.Curve = elliptic.P384()
				}
			}
			if len(args) > 1 {
				curve, ok := parseEasyRSACurve(args[1])
				if !ok {
					return fmt.Errorf("unknown curve %q", args[1])
				}
				cfg.Curve = curve
			}
			_, err = pki.NewWithFS(opts.pkiDir, cfg)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "initialized PKI at %s\n", opts.pkiDir)
			return nil
		},
	}
}

func newBuildCACmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "build-ca [nopass]",
		Short: "Create a new CA",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmdOpts, err := parseCommandOpts(args, "nopass", "subca", "rawca")
			if err != nil {
				return err
			}
			if cmdOpts["rawca"] || strings.TrimSpace(opts.rawCA) != "" {
				return fmt.Errorf("go-easyrsa: raw CA password input is not implemented yet")
			}
			pk, cfg, err := openPKI(opts, func(cfg *pki.Config) {
				if opts.days > 0 {
					cfg.CADays = opts.days
				}
			})
			if err != nil {
				return err
			}
			buildOpts, err := buildCommonOptions(opts, cfg, "", commandScopeCA, nil, cmdOpts)
			if err != nil {
				return err
			}
			reqCN := strings.TrimSpace(opts.reqCN)
			if reqCN == "" || reqCN == "ChangeMe" {
				cn := "Easy-RSA CA"
				if cmdOpts["subca"] {
					cn = "Easy-RSA Sub-CA"
				}
				buildOpts = append(buildOpts, pki.WithCN(cn))
			}
			pair, err := pk.BuildCA(buildOpts...)
			if err != nil {
				return err
			}
			return printPairSummary(cmd, pair)
		},
	}
}

func newRenewCACmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "renew-ca",
		Short: "Renew the CA certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, cfg, err := openPKI(opts, func(cfg *pki.Config) {
				if opts.days > 0 {
					cfg.CADays = opts.days
				}
			})
			if err != nil {
				return err
			}
			buildOpts, err := buildCommonOptions(opts, cfg, "", commandScopeCA, nil, nil)
			if err != nil {
				return err
			}
			pair, err := pk.RenewCA(buildOpts...)
			if err != nil {
				return err
			}
			return printPairSummary(cmd, pair)
		},
	}
}

func newGenReqCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "gen-req <name> [nopass]",
		Short: "Generate a key and CSR",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cmdOpts, err := parseCommandOpts(args[1:], "nopass")
			if err != nil {
				return err
			}
			pk, cfg, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			buildOpts, err := buildCommonOptions(opts, cfg, name, commandScopeCSR, nil, cmdOpts)
			if err != nil {
				return err
			}
			csrPEM, err := pk.GenReq(name, buildOpts...)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(csrPEM)
			return err
		},
	}
}

func newImportReqCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "import-req <request_file_path> <short_name_base>",
		Short: "Import a CSR from a file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(filepath.Clean(args[0]))
			if err != nil {
				return err
			}
			return pk.ImportReq(args[1], data)
		},
	}
}

func newSignReqCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "sign-req <type> <name> [newsubj|preserve]",
		Short: "Sign a stored CSR",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			certType, err := parseCertType(args[0])
			if err != nil {
				return err
			}
			name := args[1]
			cmdOpts, err := parseCommandOpts(args[2:], "newsubj", "preserve")
			if err != nil {
				return err
			}
			pk, cfg, err := openPKI(opts, func(cfg *pki.Config) {
				if opts.days > 0 {
					cfg.DefaultDays = opts.days
				}
			})
			if err != nil {
				return err
			}
			buildOpts, err := buildCommonOptions(opts, cfg, name, commandScopeSign, &certType, cmdOpts)
			if err != nil {
				return err
			}
			pair, err := pk.SignReq(name, certType, buildOpts...)
			if err != nil {
				return err
			}
			return printPairSummary(cmd, pair)
		},
	}
}

func newBuildFullCmd(opts *cliOptions, use string, certType cert.CertType) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <name> [nopass]",
		Short: "Generate and sign a certificate locally",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cmdOpts, err := parseCommandOpts(args[1:], "nopass")
			if err != nil {
				return err
			}
			pk, cfg, err := openPKI(opts, func(cfg *pki.Config) {
				if opts.days > 0 {
					cfg.DefaultDays = opts.days
				}
			})
			if err != nil {
				return err
			}
			buildOpts, err := buildCommonOptions(opts, cfg, name, commandScopeBuildFull, &certType, cmdOpts)
			if err != nil {
				return err
			}
			var pair *cert.Pair
			switch certType {
			case cert.CertTypeClient:
				pair, err = pk.BuildClientFull(name, buildOpts...)
			case cert.CertTypeServer:
				pair, err = pk.BuildServerFull(name, buildOpts...)
			default:
				pair, err = pk.BuildServerClientFull(name, buildOpts...)
			}
			if err != nil {
				return err
			}
			return printPairSummary(cmd, pair)
		},
	}
}

func newExpireCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "expire <name>",
		Short: "Move a current certificate to the expired directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateLifecycleName(args[0]); err != nil {
				return err
			}
			if _, _, err := openPKI(opts, nil); err != nil {
				return err
			}
			return movePKIFile(
				opts.pkiDir,
				filepath.Join("issued", args[0]+".crt"),
				filepath.Join("expired", args[0]+".crt"),
			)
		},
	}
}

func newRenewCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "renew <name>",
		Short: "Renew a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, cfg, err := openPKI(opts, func(cfg *pki.Config) {
				if opts.days > 0 {
					cfg.DefaultDays = opts.days
				}
			})
			if err != nil {
				return err
			}
			buildOpts, err := buildCommonOptions(opts, cfg, args[0], commandScopeRenew, nil, nil)
			if err != nil {
				return err
			}
			pair, err := pk.Renew(args[0], buildOpts...)
			if err != nil {
				return err
			}
			return printPairSummary(cmd, pair)
		},
	}
}

func newRevokeCmd(opts *cliOptions, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <name> [reason]",
		Short: "Revoke a certificate",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			reason, err := parseReason(optionalArg(args, 1))
			if err != nil {
				return err
			}
			if err := validateLifecycleName(args[0]); err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			return withLifecycleSession(opts.pkiDir, func(session *lifecycleSession) error {
				certificateFile, err := session.readRegular(filepath.Join("issued", args[0]+".crt"))
				if err != nil {
					return err
				}
				pair := &cert.Pair{Name: args[0], CertPEM: certificateFile.data}
				serial, err := pair.Serial()
				if err != nil {
					return err
				}
				staged, err := session.stageIssuedCertificate(args[0], serial, certificateFile.info)
				if err != nil {
					return err
				}
				if err := pk.RevokeBySerial(serial, reason); err != nil {
					return errors.Join(err, staged.Rollback())
				}
				if err := staged.Commit(); err != nil {
					return err
				}
				return removeRevokedExports(session, args[0])
			})
		},
	}
}

func newRevokeExpiredCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke-expired <name> [reason]",
		Short: "Revoke an expired certificate",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			reason, err := parseReason(optionalArg(args, 1))
			if err != nil {
				return err
			}
			if err := validateLifecycleName(args[0]); err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			return withLifecycleSession(opts.pkiDir, func(session *lifecycleSession) error {
				certificateFile, err := session.readRegular(filepath.Join("expired", args[0]+".crt"))
				if err != nil {
					return err
				}
				pair := &cert.Pair{Name: args[0], CertPEM: certificateFile.data}
				serial, err := pair.Serial()
				if err != nil {
					return err
				}
				staged, err := session.stageExpiredCertificate(args[0], serial, certificateFile.info)
				if err != nil {
					return err
				}
				if err := pk.RevokeBySerial(serial, reason); err != nil {
					return errors.Join(err, staged.Rollback())
				}
				return staged.Commit()
			})
		},
	}
}

func newGenCRLCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "gen-crl",
		Short: "Generate a CRL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, _, err := openPKI(opts, func(cfg *pki.Config) {
				if opts.days > 0 {
					cfg.CRLDays = opts.days
				}
			})
			if err != nil {
				return err
			}
			crlPEM, err := pk.GenCRL()
			if err != nil {
				return err
			}
			path, err := writePKIArtifact(opts.pkiDir, "crl.pem", crlPEM, 0o644)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			return err
		},
	}
}

func newGenDHCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "gen-dh",
		Short: "Generate DH parameters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			bits := opts.keySize
			if bits == 0 {
				bits = 2048
			}
			data, err := pk.GenDH(bits)
			if err != nil {
				return err
			}
			path, err := writePKIArtifact(opts.pkiDir, "dh.pem", data, 0o644)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
			return err
		},
	}
}

func newUpdateDBCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "update-db",
		Short: "Update the certificate index database",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			return pk.UpdateDB()
		},
	}
}

func newSetPassCmd(opts *cliOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-pass <name> [nopass]",
		Short: "Set a private key passphrase",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmdOpts, err := parseCommandOpts(args[1:], "nopass")
			if err != nil {
				return err
			}
			newPass, err := outputPassword(opts, cmdOpts)
			if err != nil {
				return err
			}
			pk, cfg, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			oldPass := effectivePassIn(opts, cfg)
			return pk.SetPass(args[0], oldPass, newPass)
		},
	}
	cmd.Aliases = []string{"set-rsa-pass", "set-ec-pass"}
	return cmd
}

func parseReason(value string) (cert.RevocationReason, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "us", "unspecified", "uns":
		return cert.ReasonUnspecified, nil
	case "kc", "key", "keycompromise":
		return cert.ReasonKeyCompromise, nil
	case "cc", "ca", "cacompromise":
		return cert.ReasonCACompromise, nil
	case "ac", "aff", "affiliationchanged":
		return cert.ReasonAffiliationChanged, nil
	case "ss", "sup", "superseded":
		return cert.ReasonSuperseded, nil
	case "co", "ces", "cessationofoperation":
		return cert.ReasonCessationOfOperation, nil
	default:
		return 0, fmt.Errorf("unknown revocation reason %q", value)
	}
}

func parseCertType(value string) (cert.CertType, error) {
	switch strings.TrimSpace(value) {
	case "client":
		return cert.CertTypeClient, nil
	case "server":
		return cert.CertTypeServer, nil
	case "serverClient":
		return cert.CertTypeServerClient, nil
	case "ca":
		return cert.CertTypeCA, nil
	default:
		return "", fmt.Errorf("unknown certificate type %q", value)
	}
}
