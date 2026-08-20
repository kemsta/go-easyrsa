package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func newShowReqCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-req <name> [full]",
		Short: "Show a certificate request",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := parseCommandOpts(args[1:], "full"); err != nil {
				return err
			}
			pk, _, err := openPKIReadOnly(opts)
			if err != nil {
				return err
			}
			request, err := pk.ShowReq(args[0])
			if err != nil {
				return err
			}
			info, err := request.Info()
			if err != nil {
				return err
			}
			return writeRequestSummary(cmd.OutOrStdout(), info)
		},
	}
}

func newShowEKUCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-eku <name-or-path>",
		Short: "Show a certificate's Extended Key Usage type",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pk, _, err := openPKIReadOnly(opts)
			if err != nil {
				return err
			}
			label, classifyErr := pk.ShowEKU(args[0])
			var writeErr error
			if label != "" {
				_, writeErr = fmt.Fprintln(cmd.OutOrStdout(), label)
			}
			return errors.Join(classifyErr, writeErr)
		},
	}
}

func newCheckSerialCmd(opts *cliOptions, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <serial> [batch]",
		Short: "Check whether a certificate serial is present in the index",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			commandOptions, err := parseCommandOpts(args[1:], "batch")
			if err != nil {
				return err
			}
			serial, err := parseHexSerial(args[0])
			if err != nil {
				return err
			}
			pk, _, err := openPKIReadOnly(opts)
			if err != nil {
				return err
			}
			var entry *storage.IndexEntry
			if use == "serial" {
				entry, err = pk.Serial(serial)
			} else {
				entry, err = pk.CheckSerial(serial)
			}
			if err != nil {
				return err
			}
			batch := opts.batch || commandOptions["batch"]
			if batch {
				if entry != nil {
					return errSilentExit
				}
				return nil
			}
			if entry == nil {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Serial %s is available\n", storage.HexSerial(serial))
				return err
			}
			_, err = fmt.Fprintf(
				cmd.OutOrStdout(),
				"Serial %s status=%s subject=%s\n",
				storage.HexSerial(serial),
				entry.Status,
				entry.Subject.String(),
			)
			return err
		},
	}
}

func newDisplayDNCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "display-dn <x509|req> <path>",
		Short: "Display a certificate or request distinguished name",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			form := pki.DNForm(strings.ToLower(args[0]))
			if form != pki.DNFormX509 && form != pki.DNFormRequest {
				return fmt.Errorf("go-easyrsa: unsupported DN format %q (expected x509 or req)", args[0])
			}
			pk, err := pki.NewWithMemory(pki.Config{})
			if err != nil {
				return err
			}
			rdns, err := pk.DisplayDN(form, args[1])
			if err != nil {
				return err
			}
			return writeRDNSequence(cmd.OutOrStdout(), rdns)
		},
	}
}

func newRandCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rand <bytes>",
		Short: "Generate cryptographically random lowercase hex",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			count, err := parseRandomByteCount(args[0])
			if err != nil {
				return err
			}
			pk, err := pki.NewWithMemory(pki.Config{})
			if err != nil {
				return err
			}
			return pk.Rand(count, cmd.OutOrStdout())
		},
	}
}

func parseHexSerial(value string) (*big.Int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F')
	}) >= 0 {
		return nil, fmt.Errorf("go-easyrsa: invalid hexadecimal serial %q", value)
	}
	serial := new(big.Int)
	if _, ok := serial.SetString(value, 16); !ok {
		return nil, fmt.Errorf("go-easyrsa: invalid hexadecimal serial %q", value)
	}
	return serial, nil
}

func parseRandomByteCount(value string) (int64, error) {
	if value == "" || value[0] == '0' || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, fmt.Errorf("go-easyrsa: random byte count must be a positive decimal integer")
	}
	count, err := strconv.ParseInt(value, 10, 64)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("go-easyrsa: random byte count must be a positive decimal integer")
	}
	return count, nil
}

func writeRequestSummary(destination io.Writer, info *certpkg.RequestInfo) error {
	if _, err := fmt.Fprintf(destination, "name=%s\n", info.Name); err != nil {
		return err
	}
	if err := writeRDNSequence(destination, info.Subject); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "dns=%s\n", strings.Join(info.DNSNames, ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "ips=%s\n", strings.Join(ipStrings(info.IPAddresses), ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "emails=%s\n", strings.Join(info.EmailAddresses, ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "public-key=%s\n", info.PublicKey); err != nil {
		return err
	}
	_, err := fmt.Fprintf(destination, "signature-algorithm=%s\n", info.SignatureAlgorithm)
	return err
}

func writeRDNSequence(destination io.Writer, rdns pkix.RDNSequence) error {
	if _, err := fmt.Fprintln(destination, "subject="); err != nil {
		return err
	}
	for _, set := range rdns {
		for _, attribute := range set {
			if _, err := fmt.Fprintf(destination, "    %s = %s\n", attributeLabel(attribute.Type), attributeValue(attribute.Value)); err != nil {
				return err
			}
		}
	}
	return nil
}

func attributeLabel(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}):
		return "commonName"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}):
		return "countryName"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 7}):
		return "localityName"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 8}):
		return "stateOrProvinceName"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 9}):
		return "streetAddress"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 10}):
		return "organizationName"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 11}):
		return "organizationalUnitName"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 5}):
		return "serialNumber"
	case oid.Equal(asn1.ObjectIdentifier{2, 5, 4, 17}):
		return "postalCode"
	case oid.Equal(emailAddressOID):
		return "emailAddress"
	default:
		return oid.String()
	}
}

func attributeValue(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case []byte:
		return hex.EncodeToString(value)
	case asn1.RawValue:
		return hex.EncodeToString(value.FullBytes)
	default:
		return fmt.Sprint(value)
	}
}

func ipStrings(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}
