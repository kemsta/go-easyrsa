package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func newExportP12Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p12 <name> [nopass|noca|nokey|nofn|legacy]",
		Short: "Export a PKCS#12 bundle",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			commandOptions, err := parseCommandOpts(args[1:], "nopass", "noca", "nokey", "nofn", "legacy")
			if err != nil {
				return err
			}
			if opts.useFN != "" || commandOptions["nofn"] {
				return errors.New("go-easyrsa: PKCS#12 friendlyName customization is not implemented yet")
			}
			exportOptions, err := exportP12Options(opts, commandOptions)
			if err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			_, err = pk.ExportP12(args[0], exportOptions)
			if err != nil {
				return err
			}
			return printArtifactPath(cmd, opts.pkiDir, filepath.Join("private", args[0]+".p12"))
		},
	}
}

func newExportP7Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p7 <name> [noca]",
		Short: "Export a PKCS#7 bundle",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			commandOptions, err := parseCommandOpts(args[1:], "noca")
			if err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			if _, err := pk.ExportP7(args[0], exportP7Options(commandOptions)); err != nil {
				return err
			}
			return printArtifactPath(cmd, opts.pkiDir, filepath.Join("issued", args[0]+".p7b"))
		},
	}
}

func newExportP8Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p8 <name> [nopass]",
		Short: "Export a PKCS#8 private key",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			commandOptions, err := parseCommandOpts(args[1:], "nopass")
			if err != nil {
				return err
			}
			password, err := outputPassword(opts, commandOptions)
			if err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			if _, err := pk.ExportP8(args[0], password); err != nil {
				return err
			}
			return printArtifactPath(cmd, opts.pkiDir, filepath.Join("private", args[0]+".p8"))
		},
	}
}

func newExportP1Cmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "export-p1 <name> [nopass]",
		Short: "Export a PKCS#1 private key",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			commandOptions, err := parseCommandOpts(args[1:], "nopass")
			if err != nil {
				return err
			}
			password, err := outputPassword(opts, commandOptions)
			if err != nil {
				return err
			}
			pk, _, err := openPKI(opts, nil)
			if err != nil {
				return err
			}
			if _, err := pk.ExportP1(args[0], password); err != nil {
				return err
			}
			return printArtifactPath(cmd, opts.pkiDir, filepath.Join("private", args[0]+".p1"))
		},
	}
}

func exportP12Options(opts *cliOptions, commandOptions map[string]bool) (pki.ExportP12Options, error) {
	password, err := outputPassword(opts, commandOptions)
	if err != nil {
		return pki.ExportP12Options{}, err
	}
	return pki.ExportP12Options{
		Password: password,
		NoCA:     commandOptions["noca"],
		NoKey:    commandOptions["nokey"],
		Legacy:   commandOptions["legacy"],
	}, nil
}

func exportP7Options(commandOptions map[string]bool) pki.ExportP7Options {
	return pki.ExportP7Options{NoCA: commandOptions["noca"]}
}

func printArtifactPath(cmd *cobra.Command, pkiDir, relative string) error {
	name, err := filepath.Abs(filepath.Join(pkiDir, relative))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", name)
	return err
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

func outputPassword(opts *cliOptions, commandOptions map[string]bool) (string, error) {
	if opts.noPass || commandOptions["nopass"] {
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
