package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kemsta/go-easyrsa/v2/cert"
)

func newRootCmd() *cobra.Command {
	opts := defaultCLIOptions()

	cmd := &cobra.Command{
		Use:           "go-easyrsa",
		Short:         "easy-rsa compatible CLI powered by go-easyrsa",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateCLIInputs(cmd, &opts); err != nil {
				return err
			}
			return validateUnsupportedResultAffectingEnv()
		},
	}

	cmd.PersistentFlags().StringVar(&opts.pkiDir, "pki-dir", opts.pkiDir, "PKI directory (defaults to EASYRSA_PKI or ./pki)")
	cmd.PersistentFlags().IntVar(&opts.days, "days", opts.days, "certificate / CRL / show-expire day window override")
	cmd.PersistentFlags().StringVar(&opts.startDate, "startdate", opts.startDate, "certificate notBefore in [YY]YYMMDDhhmmssZ format")
	cmd.PersistentFlags().StringVar(&opts.endDate, "enddate", opts.endDate, "certificate notAfter in [YY]YYMMDDhhmmssZ format")
	cmd.PersistentFlags().StringVar(&opts.algo, "algo", opts.algo, "key algorithm: rsa|ec|ed")
	cmd.PersistentFlags().IntVar(&opts.keySize, "keysize", opts.keySize, "RSA key size")
	cmd.PersistentFlags().StringVar(&opts.curve, "curve", opts.curve, "elliptic curve name")
	cmd.PersistentFlags().IntVar(&opts.subcaLen, "subca-len", opts.subcaLen, "sub-CA path length")
	cmd.PersistentFlags().BoolVar(&opts.copyExt, "copy-ext", opts.copyExt, "copy CSR extensions when signing")
	cmd.PersistentFlags().StringArrayVar(&opts.sans, "san", opts.sans, "subjectAltName entry (repeatable)")
	cmd.PersistentFlags().StringArrayVar(&opts.subjectAltNames, "subject-alt-name", opts.subjectAltNames, "subjectAltName entry (repeatable)")
	cmd.PersistentFlags().BoolVar(&opts.autoSAN, "auto-san", opts.autoSAN, "derive SAN from commonName")
	cmd.PersistentFlags().StringVar(&opts.newSubject, "new-subject", opts.newSubject, "replacement subject when signing a CSR")
	cmd.PersistentFlags().StringVar(&opts.useFN, "usefn", opts.useFN, "friendlyName for export-p12 (currently informational)")
	cmd.PersistentFlags().StringVar(&opts.dnMode, "dn-mode", opts.dnMode, "distinguished name mode: cn_only|org")
	cmd.PersistentFlags().StringVar(&opts.reqCN, "req-cn", opts.reqCN, "request commonName override")
	cmd.PersistentFlags().StringVar(&opts.reqC, "req-c", opts.reqC, "request country")
	cmd.PersistentFlags().StringVar(&opts.reqST, "req-st", opts.reqST, "request state / province")
	cmd.PersistentFlags().StringVar(&opts.reqCity, "req-city", opts.reqCity, "request city / locality")
	cmd.PersistentFlags().StringVar(&opts.reqOrg, "req-org", opts.reqOrg, "request organization")
	cmd.PersistentFlags().StringVar(&opts.reqEmail, "req-email", opts.reqEmail, "request email address")
	cmd.PersistentFlags().StringVar(&opts.reqOU, "req-ou", opts.reqOU, "request organizational unit")
	cmd.PersistentFlags().StringVar(&opts.reqSerial, "req-serial", opts.reqSerial, "request subject serialNumber")
	cmd.PersistentFlags().BoolVar(&opts.noPass, "nopass", opts.noPass, "do not use passwords")
	cmd.PersistentFlags().BoolVar(&opts.noPass, "no-pass", opts.noPass, "do not use passwords")
	cmd.PersistentFlags().StringVar(&opts.passIn, "passin", opts.passIn, "input passphrase (e.g. pass:secret)")
	cmd.PersistentFlags().StringVar(&opts.passOut, "passout", opts.passOut, "output passphrase (e.g. pass:secret)")
	cmd.PersistentFlags().Lookup("passin").DefValue = ""
	cmd.PersistentFlags().Lookup("passout").DefValue = ""
	cmd.PersistentFlags().BoolVar(&opts.batch, "batch", opts.batch, "batch mode (accepted for compatibility)")

	cmd.AddCommand(
		newInitPKICmd(&opts),
		newBuildCACmd(&opts),
		newRenewCACmd(&opts),
		newGenReqCmd(&opts),
		newImportReqCmd(&opts),
		newSignReqCmd(&opts),
		newBuildFullCmd(&opts, "build-client-full", cert.CertTypeClient),
		newBuildFullCmd(&opts, "build-server-full", cert.CertTypeServer),
		newBuildFullCmd(&opts, "build-serverClient-full", cert.CertTypeServerClient),
		newExpireCmd(&opts),
		newRenewCmd(&opts),
		newRevokeCmd(&opts, "revoke"),
		newRevokeCmd(&opts, "revoke-issued"),
		newRevokeExpiredCmd(&opts),
		newGenCRLCmd(&opts),
		newShowCertCmd(&opts),
		newShowCACmd(&opts),
		newShowCRLCmd(&opts),
		newShowExpireCmd(&opts),
		newShowRevokeCmd(&opts),
		newVerifyCertCmd(&opts),
		newExportP12Cmd(&opts),
		newExportP7Cmd(&opts),
		newExportP8Cmd(&opts),
		newExportP1Cmd(&opts),
		newGenDHCmd(&opts),
		newUpdateDBCmd(&opts),
		newSetPassCmd(&opts),
	)
	return cmd
}

func validateCLIInputs(cmd *cobra.Command, opts *cliOptions) error {
	flags := cmd.Root().PersistentFlags()
	opts.noPassSet = flags.Changed("nopass") || flags.Changed("no-pass")
	if flags.Changed("days") && opts.days <= 0 {
		return fmt.Errorf("go-easyrsa: --days must be a positive integer")
	}
	if flags.Changed("keysize") && opts.keySize <= 0 {
		return fmt.Errorf("go-easyrsa: --keysize must be a positive integer")
	}
	if flags.Changed("subca-len") && opts.subcaLen < 0 {
		return fmt.Errorf("go-easyrsa: --subca-len must be a non-negative integer")
	}
	if opts.passOut != "" && parsePassEnv(opts.passOut) == "" {
		return fmt.Errorf("go-easyrsa: output passphrase must not be empty; use nopass explicitly")
	}
	if err := validateRSAKeySize(cmd, opts); err != nil {
		return err
	}
	return validateNumericEnv()
}

func validateRSAKeySize(cmd *cobra.Command, opts *cliOptions) error {
	if opts.keySize == 0 || opts.keySize >= 1024 {
		return nil
	}
	switch cmd.Name() {
	case "build-ca", "gen-req", "build-client-full", "build-server-full", "build-serverClient-full":
	default:
		return nil
	}
	algo, ok := parseEasyRSAAlgo(opts.algo)
	if opts.algo != "" && !ok {
		return nil
	}
	if opts.algo == "" || algo == "rsa" {
		return fmt.Errorf("go-easyrsa: RSA key size must be at least 1024 bits")
	}
	return nil
}
