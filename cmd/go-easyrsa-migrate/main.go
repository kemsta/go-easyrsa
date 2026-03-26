package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var fromPath string
	var toPath string
	var fromType string
	var toType string
	var caName string

	cmd := &cobra.Command{
		Use:   "go-easyrsa-migrate",
		Short: "Migrate PKI data between go-easyrsa storage backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromPath == "" || toPath == "" {
				return fmt.Errorf("both --from and --to are required")
			}
			if filepath.Clean(fromPath) == filepath.Clean(toPath) {
				return fmt.Errorf("source and target must differ")
			}
			if err := ensureDirExists(fromPath); err != nil {
				return fmt.Errorf("source: %w", err)
			}
			if err := ensureTargetEmpty(toPath); err != nil {
				return fmt.Errorf("target: %w", err)
			}

			source, err := openSourcePKI(fromType, fromPath, caName)
			if err != nil {
				return err
			}
			snapshot, err := source.ExportSnapshot()
			if err != nil {
				return err
			}

			target, err := openTargetPKI(toType, toPath, snapshot.CAName)
			if err != nil {
				return err
			}
			if err := target.ImportSnapshot(snapshot, source.ExportPairs); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "migrated %d indexed certificates from %s (%s) to %s (%s)\n", len(snapshot.Index), fromPath, fromType, toPath, toType)
			return nil
		},
	}

	cmd.Flags().StringVar(&fromPath, "from", "", "source PKI directory")
	cmd.Flags().StringVar(&toPath, "to", "", "target PKI directory")
	cmd.Flags().StringVar(&fromType, "from-type", "legacy-fs", "source backend type: legacy-fs|fs")
	cmd.Flags().StringVar(&toType, "to-type", "fs", "target backend type: fs")
	cmd.Flags().StringVar(&caName, "ca-name", "ca", "storage name of the CA entry in the source PKI")
	return cmd
}

func openSourcePKI(kind, dir, caName string) (*pki.PKI, error) {
	cfg := pki.Config{CAName: caName}
	switch kind {
	case "legacy-fs":
		return pki.NewWithLegacyFSRO(dir, cfg)
	case "fs":
		return pki.NewWithFS(dir, cfg)
	default:
		return nil, fmt.Errorf("unsupported source backend type %q", kind)
	}
}

func openTargetPKI(kind, dir, caName string) (*pki.PKI, error) {
	cfg := pki.Config{CAName: caName}
	switch kind {
	case "fs":
		return pki.NewWithFS(dir, cfg)
	default:
		return nil, fmt.Errorf("unsupported target backend type %q", kind)
	}
}

func ensureDirExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func ensureTargetEmpty(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s already exists and is not empty", path)
	}
	return nil
}
