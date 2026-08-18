package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kemsta/go-easyrsa/v2/cert"
)

func newShowCertCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-cert <name> [full]",
		Short: "Show a certificate",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := parseCommandOpts(args[1:], "full"); err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			pair, err := pk.ShowCert(args[0])
			if err != nil {
				return err
			}
			return printPairSummary(cmd, pair)
		},
	}
}

func newShowCACmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-ca [full]",
		Short: "Show the CA certificate",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := parseCommandOpts(args, "full"); err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			pair, err := pk.ShowCA()
			if err != nil {
				return err
			}
			return printPairSummary(cmd, pair)
		},
	}
}

func newShowCRLCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-crl",
		Short: "Show the current CRL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			crl, err := pk.ShowCRL()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "CRL number=%v revoked=%d\n", crl.Number, len(crl.RevokedCertificateEntries))
			return err
		},
	}
}

func newShowExpireCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-expire [days|name]",
		Short: "Show certificates expiring within the configured window",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, cfg, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			within := cfg.PreExpiryDays
			if opts.days > 0 {
				within = opts.days
			}
			filterName := ""
			if len(args) == 1 {
				if parsed, ok := parseInt(strings.TrimSpace(args[0])); ok {
					within = parsed
				} else {
					filterName = args[0]
				}
			}
			pairs, err := pk.ShowExpiring(within)
			if err != nil {
				return err
			}
			if filterName != "" {
				pairs = filterPairsByName(pairs, filterName)
			}
			return printPairList(cmd, pairs)
		},
	}
}

func newShowRevokeCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-revoke [name]",
		Short: "Show revoked certificates",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			pairs, err := pk.ShowRevoked()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				pairs = filterPairsByName(pairs, args[0])
			}
			return printPairList(cmd, pairs)
		},
	}
}

func newVerifyCertCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "verify-cert <name> [batch]",
		Short: "Verify a certificate against the CA and CRL",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := parseCommandOpts(args[1:], "batch"); err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			if err := pk.VerifyCert(args[0]); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "OK")
			return err
		},
	}
}

func printPairSummary(cmd *cobra.Command, pair *cert.Pair) error {
	certificate, err := pair.Certificate()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %s expires=%s key=%t\n", pair.Name, certificate.Subject, certificate.NotAfter.UTC().Format(time.RFC3339), pair.HasKey())
	return err
}

func printPairList(cmd *cobra.Command, pairs []*cert.Pair) error {
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Name < pairs[j].Name })
	for _, pair := range pairs {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), pair.Name); err != nil {
			return err
		}
	}
	return nil
}

func filterPairsByName(pairs []*cert.Pair, name string) []*cert.Pair {
	var filtered []*cert.Pair
	for _, pair := range pairs {
		if pair.Name == name {
			filtered = append(filtered, pair)
		}
	}
	return filtered
}
