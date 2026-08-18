package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
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
			parsed, err := request.Request()
			if err != nil {
				return err
			}
			return writeRequestSummary(cmd.OutOrStdout(), request.Name, parsed)
		},
	}
}

func newShowEKUCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show-eku <name-or-path>",
		Short: "Show a certificate's Extended Key Usage type",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			label, classifyErr, err := classifyEKUArgument(opts, args[0])
			if err != nil {
				return err
			}
			_, writeErr := fmt.Fprintln(cmd.OutOrStdout(), label)
			return errors.Join(classifyErr, writeErr)
		},
	}
}

func classifyEKUArgument(opts *cliOptions, nameOrPath string) (certpkg.EKUType, error, error) {
	file, regular, err := openRegularPath(nameOrPath)
	if err != nil {
		return "", nil, err
	}
	if regular {
		data, readErr := readAndClose(file)
		if readErr != nil {
			return "", nil, readErr
		}
		certificate, parseErr := parseCertificatePEM(data)
		if parseErr != nil {
			return "", nil, parseErr
		}
		label, classifyErr := certpkg.ClassifyEKU(certificate)
		return label, classifyErr, nil
	}

	pk, _, err := openPKIReadOnly(opts)
	if err != nil {
		return "", nil, err
	}
	label, classifyErr := pk.ShowEKU(nameOrPath)
	return label, classifyErr, nil
}

func newCheckSerialCmd(opts *cliOptions, use string) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <serial> [batch]",
		Short: "Check whether a certificate serial is present in the index",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			commandOpts, err := parseCommandOpts(args[1:], "batch")
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
			entry, err := pk.CheckSerial(serial)
			if err != nil {
				return err
			}
			batch := opts.batch || commandOpts["batch"]
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
			format := strings.ToLower(args[0])
			if format != "x509" && format != "req" {
				return fmt.Errorf("go-easyrsa: unsupported DN format %q (expected x509 or req)", args[0])
			}
			data, err := readExplicitRegularFile(args[1])
			if err != nil {
				return err
			}
			rdns, err := parseSubjectRDN(format, data)
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
			return writeRandomHex(cmd.OutOrStdout(), cryptorand.Reader, count)
		},
	}
}

func parseHexSerial(value string) (*big.Int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
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

func writeRandomHex(destination io.Writer, source io.Reader, count int64) error {
	if count <= 0 {
		return errors.New("go-easyrsa: random byte count must be positive")
	}
	written, err := io.CopyN(hex.NewEncoder(destination), source, count)
	if err != nil {
		return fmt.Errorf("go-easyrsa: generate random bytes: %w", err)
	}
	if written != count {
		return fmt.Errorf("go-easyrsa: generated %d random bytes, expected %d", written, count)
	}
	if _, err := fmt.Fprintln(destination); err != nil {
		return fmt.Errorf("go-easyrsa: write random output: %w", err)
	}
	return nil
}

func openRegularPath(path string) (*os.File, bool, error) {
	return openRegularPathWith(path, openReadOnlyPath)
}

func openRegularPathWith(path string, opener func(string) (*os.File, error)) (*os.File, bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, nil
	}

	file, err := opener(path)
	if err != nil {
		return nil, false, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil {
		return nil, false, errors.Join(statErr, file.Close())
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, false, file.Close()
	}
	return file, true, nil
}

func readExplicitRegularFile(path string) ([]byte, error) {
	file, regular, err := openRegularPath(path)
	if err != nil {
		return nil, err
	}
	if !regular {
		return nil, fmt.Errorf("go-easyrsa: path is not a regular file: %s", path)
	}
	return readAndClose(file)
}

func readAndClose(file *os.File) ([]byte, error) {
	data, readErr := io.ReadAll(file)
	return data, errors.Join(readErr, file.Close())
}

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("go-easyrsa: failed to decode certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("go-easyrsa: parse certificate: %w", err)
	}
	return certificate, nil
}

func parseSubjectRDN(format string, data []byte) (pkix.RDNSequence, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("go-easyrsa: failed to decode PEM input")
	}
	var rawSubject []byte
	switch format {
	case "x509":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("go-easyrsa: parse certificate: %w", err)
		}
		rawSubject = certificate.RawSubject
	case "req":
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("go-easyrsa: parse certificate request: %w", err)
		}
		rawSubject = request.RawSubject
	default:
		return nil, fmt.Errorf("go-easyrsa: unsupported DN format %q (expected x509 or req)", format)
	}

	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(rawSubject, &rdns)
	if err != nil {
		return nil, fmt.Errorf("go-easyrsa: parse subject DN: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("go-easyrsa: trailing data in subject DN")
	}
	return rdns, nil
}

func writeRequestSummary(destination io.Writer, name string, request *x509.CertificateRequest) error {
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(request.RawSubject, &rdns)
	if err != nil {
		return fmt.Errorf("go-easyrsa: parse request subject: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("go-easyrsa: trailing data in request subject")
	}
	if _, err := fmt.Fprintf(destination, "name=%s\n", name); err != nil {
		return err
	}
	if err := writeRDNSequence(destination, rdns); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "dns=%s\n", strings.Join(request.DNSNames, ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "ips=%s\n", strings.Join(ipStrings(request.IPAddresses), ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "emails=%s\n", strings.Join(request.EmailAddresses, ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "public-key=%s\n", publicKeySummary(request.PublicKey)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(destination, "signature-algorithm=%s\n", request.SignatureAlgorithm)
	return err
}

func publicKeySummary(publicKey any) string {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", key.N.BitLen())
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params() == nil {
			return "ECDSA-unknown"
		}
		return "ECDSA-" + key.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", publicKey)
	}
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
