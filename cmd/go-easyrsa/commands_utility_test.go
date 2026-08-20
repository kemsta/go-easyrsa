package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

func TestUtilityCommandsRegistered(t *testing.T) {
	root := newRootCmd()
	registered := make(map[string]bool)
	for _, command := range root.Commands() {
		registered[command.Name()] = true
	}
	for _, name := range []string{"show-req", "show-eku", "serial", "check-serial", "display-dn", "rand"} {
		assert.Truef(t, registered[name], "%s is not registered", name)
	}
}

func TestCLI_ShowReq(t *testing.T) {
	dir := t.TempDir()
	pk := openFS(t, dir, pki.Config{NoPass: true, DNMode: pki.DNModeOrg})
	subject := pkix.Name{
		CommonName:         "Alice Client",
		Country:            []string{"PL"},
		Province:           []string{"Mazovia"},
		Locality:           []string{"Warsaw"},
		Organization:       []string{"Example Org"},
		OrganizationalUnit: []string{"VPN"},
		SerialNumber:       "SUBJECT-42",
		ExtraNames: []pkix.AttributeTypeAndValue{{
			Type:  emailAddressOID,
			Value: "alice@example.test",
		}},
	}
	_, err := pk.GenReq(
		"alice",
		pki.WithSubject(subject),
		pki.WithSubjectSerial("SUBJECT-42"),
		pki.WithDNSNames("alice.example.test"),
		pki.WithIPAddresses(net.ParseIP("192.0.2.10")),
		pki.WithEmailAddresses("san@example.test"),
	)
	require.NoError(t, err)

	for _, extra := range [][]string{nil, {"full"}} {
		args := append([]string{"--pki-dir", dir, "show-req", "alice"}, extra...)
		out, err := runCLI(t, args...)
		require.NoError(t, err, out)
		for _, expected := range []string{
			"name=alice",
			"commonName = Alice Client",
			"countryName = PL",
			"organizationName = Example Org",
			"organizationalUnitName = VPN",
			"serialNumber = SUBJECT-42",
			"emailAddress = alice@example.test",
			"dns=alice.example.test",
			"ips=192.0.2.10",
			"emails=san@example.test",
			"public-key=RSA-2048",
			"signature-algorithm=SHA256-RSA",
		} {
			assert.Contains(t, out, expected)
		}
	}

	_, err = runCLI(t, "--pki-dir", dir, "show-req", "alice", "unknown")
	assert.Error(t, err)
}

func TestCLI_ShowReqDoesNotInitializeMissingPKI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	_, err := runCLI(t, "--pki-dir", dir, "show-req", "alice")
	require.Error(t, err)
	_, statErr := os.Stat(dir)
	assert.ErrorIs(t, statErr, fs.ErrNotExist)
}

func TestCLI_ShowEKUByNameAndPath(t *testing.T) {
	dir := t.TempDir()
	pk := openFS(t, dir, pki.Config{NoPass: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	client, err := pk.BuildClientFull("alice")
	require.NoError(t, err)
	_, err = pk.BuildServerFull("server")
	require.NoError(t, err)
	_, err = pk.BuildServerClientFull("dual")
	require.NoError(t, err)
	_, err = pk.BuildClientFull("code", pki.WithCertModifier(func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}))
	require.NoError(t, err)

	for _, tt := range []struct {
		name string
		want string
	}{
		{name: "alice", want: "client\n"},
		{name: "server", want: "server\n"},
		{name: "dual", want: "serverClient\n"},
		{name: "code", want: "codeSigning\n"},
	} {
		out, err := runCLI(t, "--pki-dir", dir, "show-eku", tt.name)
		require.NoError(t, err, out)
		assert.Equal(t, tt.want, out)
	}

	path := filepath.Join(t.TempDir(), "external.crt")
	require.NoError(t, os.WriteFile(path, client.CertPEM, 0o600))
	out, err := runCLI(t, "--pki-dir", filepath.Join(t.TempDir(), "missing"), "show-eku", path)
	require.NoError(t, err, out)
	assert.Equal(t, "client\n", out)

	link := filepath.Join(t.TempDir(), "external-link.crt")
	require.NoError(t, os.Symlink(path, link))
	out, err = runCLI(t, "--pki-dir", filepath.Join(t.TempDir(), "missing"), "show-eku", link)
	require.NoError(t, err, out)
	assert.Equal(t, "client\n", out)
}

func TestCLI_ShowEKUNonRegularPathFallsBackToName(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
	require.NoError(t, os.Mkdir("alice", 0o755))

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk := openFS(t, pkiDir, pki.Config{NoPass: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("alice")
	require.NoError(t, err)

	out, err := runCLI(t, "--pki-dir", pkiDir, "show-eku", "alice")
	require.NoError(t, err, out)
	assert.Equal(t, "client\n", out)
}

func TestCLI_ShowEKUMalformedRegularFileDoesNotFallBack(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
	require.NoError(t, os.WriteFile("alice", []byte("not a certificate"), 0o600))

	pkiDir := filepath.Join(t.TempDir(), "pki")
	pk := openFS(t, pkiDir, pki.Config{NoPass: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("alice")
	require.NoError(t, err)

	out, err := runCLI(t, "--pki-dir", pkiDir, "show-eku", "alice")
	assert.Empty(t, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode certificate PEM")
}

func TestCLI_ShowEKUUnknownPrintsLabelAndFails(t *testing.T) {
	dir := t.TempDir()
	pk := openFS(t, dir, pki.Config{NoPass: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("undefined", pki.WithCertModifier(func(c *x509.Certificate) {
		c.ExtKeyUsage = nil
	}))
	require.NoError(t, err)

	out, err := runCLI(t, "--pki-dir", dir, "show-eku", "undefined")
	assert.Equal(t, "undefined\n", out)
	require.Error(t, err)
	assert.ErrorIs(t, err, certpkg.ErrUnknownEKU)
}

func TestCLI_SerialAliasesAndBatchModes(t *testing.T) {
	dir := t.TempDir()
	pk := openFS(t, dir, pki.Config{NoPass: true, SequentialSerial: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	pair, err := pk.BuildClientFull("alice")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)
	existing := strings.ToUpper(serial.Text(16))
	available := "deadbeef"
	serialPath := filepath.Join(dir, "serial")
	serialBefore, err := os.ReadFile(serialPath)
	require.NoError(t, err)

	for _, name := range []string{"serial", "check-serial"} {
		out, err := runCLI(t, "--pki-dir", dir, name, existing)
		require.NoError(t, err, out)
		assert.Contains(t, out, "status=V")
		assert.Contains(t, out, storage.HexSerial(serial))

		out, err = runCLI(t, "--pki-dir", dir, name, available)
		require.NoError(t, err, out)
		assert.Contains(t, out, "DEADBEEF is available")

		out, err = runCLI(t, "--pki-dir", dir, name, available, "batch")
		require.NoError(t, err, out)
		assert.Empty(t, out)

		out, err = runCLI(t, "--pki-dir", dir, name, existing, "batch")
		assert.Empty(t, out)
		assert.ErrorIs(t, err, errSilentExit)
	}

	out, err := runCLI(t, "--pki-dir", dir, "--batch", "check-serial", available)
	require.NoError(t, err, out)
	assert.Empty(t, out)

	t.Setenv("EASYRSA_BATCH", "1")
	out, err = runCLI(t, "--pki-dir", dir, "check-serial", available)
	require.NoError(t, err, out)
	assert.Empty(t, out)

	serialAfter, err := os.ReadFile(serialPath)
	require.NoError(t, err)
	assert.Equal(t, serialBefore, serialAfter)
}

func TestCLISerialOccupiedBatchIsSilentInMain(t *testing.T) {
	dir := t.TempDir()
	pk := openFS(t, dir, pki.Config{NoPass: true, SequentialSerial: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	pair, err := pk.BuildClientFull("alice")
	require.NoError(t, err)
	serial, err := pair.Serial()
	require.NoError(t, err)

	for _, alias := range []string{"serial", "check-serial"} {
		for _, mode := range []string{"positional", "flag", "environment"} {
			t.Run(alias+"/"+mode, func(t *testing.T) {
				args := []string{"--pki-dir", dir}
				switch mode {
				case "flag":
					args = append(args, "--batch", alias, serial.Text(16))
				case "environment":
					args = append(args, alias, serial.Text(16))
				default:
					args = append(args, alias, serial.Text(16), "batch")
				}
				argv := append([]string{"-test.run=^TestCLIMainSerialBatchHelper$", "--"}, args...)
				command := exec.Command(os.Args[0], argv...)
				batchValue := "0"
				if mode == "environment" {
					batchValue = "1"
				}
				command.Env = testEnvironment(map[string]string{
					"GO_EASYRSA_MAIN_HELPER": "1",
					"EASYRSA_BATCH":          batchValue,
				})
				var stdout, stderr bytes.Buffer
				command.Stdout = &stdout
				command.Stderr = &stderr
				err := command.Run()
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr)
				assert.Equal(t, 1, exitErr.ExitCode())
				assert.Empty(t, stdout.String())
				assert.Empty(t, stderr.String())
			})
		}
	}
}

func TestCLIMainSerialBatchHelper(t *testing.T) {
	if os.Getenv("GO_EASYRSA_MAIN_HELPER") != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		os.Exit(2)
	}
	os.Args = append([]string{os.Args[0]}, os.Args[separator+1:]...)
	main()
}

func TestCLI_SerialRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{"-1", "+1", "0x10", "xyz", "12:34"} {
		_, err := runCLI(t, "check-serial", value)
		assert.Errorf(t, err, "value %q", value)
	}
	_, err := runCLI(t, "check-serial", "01", "unknown")
	assert.Error(t, err)
}

func TestCLI_DisplayDNPreservesRawRDNs(t *testing.T) {
	certificatePEM, requestPEM, labels := makeRawSubjectArtifacts(t)
	for _, tt := range []struct {
		format string
		data   []byte
	}{
		{format: "x509", data: certificatePEM},
		{format: "req", data: requestPEM},
	} {
		path := filepath.Join(t.TempDir(), "subject.pem")
		require.NoError(t, os.WriteFile(path, tt.data, 0o600))
		out, err := runCLI(t, "display-dn", tt.format, path)
		require.NoError(t, err, out)
		assert.True(t, strings.HasPrefix(out, "subject=\n"))
		last := -1
		for _, label := range labels {
			position := strings.Index(out, label)
			assert.Greater(t, position, last, "attribute %q is missing or out of order in %q", label, out)
			last = position
		}
	}
}

func TestCLI_DisplayDNInputValidation(t *testing.T) {
	_, err := runCLI(t, "display-dn", "unsupported", filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported DN format")

	_, err = runCLI(t, "display-dn", "x509", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")

	malformed := filepath.Join(t.TempDir(), "malformed.pem")
	require.NoError(t, os.WriteFile(malformed, []byte("not PEM"), 0o600))
	_, err = runCLI(t, "display-dn", "x509", malformed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode PEM")

	certificatePEM, _, _ := makeRawSubjectArtifacts(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target.crt")
	link := filepath.Join(dir, "link.crt")
	require.NoError(t, os.WriteFile(target, certificatePEM, 0o600))
	require.NoError(t, os.Symlink(target, link))
	out, err := runCLI(t, "display-dn", "x509", link)
	require.NoError(t, err, out)
	assert.Contains(t, out, "commonName = Alice")
}

func TestCLI_Rand(t *testing.T) {
	out, err := runCLI(t, "rand", "32")
	require.NoError(t, err, out)
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{64}\n$`), out)
	other, err := runCLI(t, "rand", "32")
	require.NoError(t, err, other)
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{64}\n$`), other)

	for _, value := range []string{"", "0", "01", "-1", "+1", "1.5", "abc", "9223372036854775808"} {
		args := []string{"rand"}
		if value != "" {
			args = append(args, value)
		}
		_, err := runCLI(t, args...)
		assert.Errorf(t, err, "value %q", value)
	}
}

func TestCLI_ReadOnlyCommandsDoNotChangePKI(t *testing.T) {
	dir := t.TempDir()
	pk := openFS(t, dir, pki.Config{NoPass: true, SequentialSerial: true})
	_, err := pk.BuildCA()
	require.NoError(t, err)
	_, err = pk.BuildClientFull("alice")
	require.NoError(t, err)
	before := snapshotRawTree(t, dir)

	commands := [][]string{
		{"show-req", "alice"},
		{"show-eku", "alice"},
		{"check-serial", "deadbeef", "batch"},
		{"show-cert", "alice"},
		{"show-ca"},
		{"verify-cert", "alice", "batch"},
	}
	for _, command := range commands {
		args := append([]string{"--pki-dir", dir}, command...)
		out, err := runCLI(t, args...)
		require.NoError(t, err, "%v: %s", command, out)
		assert.Equal(t, before, snapshotRawTree(t, dir), "command %v changed the PKI", command)
	}
}

func testEnvironment(overrides map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replace := overrides[key]; !replace {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}

type rawTreeEntry struct {
	Mode fs.FileMode
	Data string
	Link string
}

func snapshotRawTree(t *testing.T, root string) map[string]rawTreeEntry {
	t.Helper()
	result := make(map[string]rawTreeEntry)
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		item := rawTreeEntry{Mode: info.Mode()}
		switch {
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.Data = string(data)
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			item.Link = link
		}
		result[rel] = item
		return nil
	}))
	return result
}

func makeRawSubjectArtifacts(t *testing.T) ([]byte, []byte, []string) {
	t.Helper()
	rdns := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Alice"}},
		{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "VPN"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Engineering"},
		},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 9}, Value: "Main Street"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 17}, Value: "00-001"}},
		{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "alice@example.test"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: "SER-42"}},
		{{Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "custom"}},
	}
	rawSubject, err := asn1.Marshal(rdns)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		RawSubject:            rawSubject,
		RawIssuer:             rawSubject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{RawSubject: rawSubject}, key)
	require.NoError(t, err)

	labels := []string{
		"commonName = Alice",
		"organizationalUnitName = VPN",
		"organizationalUnitName = Engineering",
		"streetAddress = Main Street",
		"postalCode = 00-001",
		"emailAddress = alice@example.test",
		"serialNumber = SER-42",
		"1.2.3.4.5 = custom",
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}),
		labels
}
