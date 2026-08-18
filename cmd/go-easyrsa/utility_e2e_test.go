//go:build e2e

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E_UtilityInspectionParity(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := setupUtilityParity(t)

	easyRequestResult := runReadOnlyE2ECommand(t, easyRunner, "show-req", "alice")
	require.NoError(t, easyRequestResult.err, easyRequestResult.combinedOutput())
	goRequestResult := runReadOnlyE2ECommand(t, goRunner, "show-req", "alice")
	require.NoError(t, goRequestResult.err, goRequestResult.combinedOutput())
	easyRequest := normalizeRequest(t, filepath.Join(easyDir, "reqs", "alice.req"))
	goRequest := normalizeRequest(t, filepath.Join(goDir, "reqs", "alice.req"))
	require.Equal(t, easyRequest, goRequest)
	assertRequestOutputContains(t, easyRequestResult.stdout, easyRequest)
	assertRequestOutputContains(t, goRequestResult.stdout, goRequest)
	goRequestLines := strings.Split(strings.TrimSuffix(goRequestResult.stdout, "\n"), "\n")
	require.Contains(t, goRequestLines, "public-key="+requestPublicKeyOutput(goRequest))
	require.Contains(t, goRequestLines, "signature-algorithm="+goRequest.SignatureAlgorithm)

	for _, tt := range []struct {
		name string
		want string
	}{
		{name: "alice", want: "client"},
		{name: "server", want: "server"},
		{name: "dual", want: "serverClient"},
	} {
		easyResult := runReadOnlyE2ECommand(t, easyRunner, "show-eku", tt.name)
		require.NoError(t, easyResult.err, easyResult.combinedOutput())
		goResult := runReadOnlyE2ECommand(t, goRunner, "show-eku", tt.name)
		require.NoError(t, goResult.err, goResult.combinedOutput())
		require.Equal(t, tt.want, extractEKULabel(t, easyResult.stdout))
		require.Equal(t, tt.want, extractEKULabel(t, goResult.stdout))
	}

	for _, certificatePath := range []string{
		filepath.Join(easyDir, "issued", "alice.crt"),
		filepath.Join(goDir, "issued", "alice.crt"),
	} {
		easyResult := runReadOnlyE2ECommandAcrossTrees(t, easyRunner, []string{easyDir, goDir}, "show-eku", certificatePath)
		require.NoError(t, easyResult.err, easyResult.combinedOutput())
		goResult := runReadOnlyE2ECommandAcrossTrees(t, goRunner, []string{easyDir, goDir}, "show-eku", certificatePath)
		require.NoError(t, goResult.err, goResult.combinedOutput())
		require.Equal(t, "client", extractEKULabel(t, easyResult.stdout))
		require.Equal(t, "client", extractEKULabel(t, goResult.stdout))
	}
}

func TestE2E_ShowEKUNamePathCollisionParity(t *testing.T) {
	goRunner, easyRunner, _, _ := setupUtilityParity(t)
	goRunner.workingDir = t.TempDir()
	easyRunner.workingDir = t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(goRunner.workingDir, "alice"), 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(easyRunner.workingDir, "alice"), 0o755))

	easyWorkingBefore := snapshotE2ETree(t, easyRunner.workingDir)
	goWorkingBefore := snapshotE2ETree(t, goRunner.workingDir)
	easyResult := runReadOnlyE2ECommand(t, easyRunner, "show-eku", "alice")
	require.NoError(t, easyResult.err, easyResult.combinedOutput())
	goResult := runReadOnlyE2ECommand(t, goRunner, "show-eku", "alice")
	require.NoError(t, goResult.err, goResult.combinedOutput())
	require.Equal(t, "client", extractEKULabel(t, easyResult.stdout))
	require.Equal(t, "client", extractEKULabel(t, goResult.stdout))
	require.Equal(t, easyWorkingBefore, snapshotE2ETree(t, easyRunner.workingDir))
	require.Equal(t, goWorkingBefore, snapshotE2ETree(t, goRunner.workingDir))
}

func TestE2E_SerialAliasesParity(t *testing.T) {
	goRunner, easyRunner, _, _ := setupUtilityParity(t)
	for _, alias := range []string{"serial", "check-serial"} {
		easyResult := runReadOnlyE2ECommand(t, easyRunner, alias, "deadbeef", "batch")
		require.NoError(t, easyResult.err, easyResult.combinedOutput())
		require.Empty(t, easyResult.stdout)
		require.Empty(t, easyResult.stderr)
		goResult := runReadOnlyE2ECommand(t, goRunner, alias, "deadbeef", "batch")
		require.NoError(t, goResult.err, goResult.combinedOutput())
		require.Empty(t, goResult.stdout)
		require.Empty(t, goResult.stderr)
	}
}

func TestE2E_OccupiedSerialSharedPKIParity(t *testing.T) {
	for _, producerName := range []string{"Easy-RSA", "Go"} {
		t.Run(producerName, func(t *testing.T) {
			dir := t.TempDir()
			goRunner, easyRunner := runnersForSharedPKI(t, dir)
			producer := easyRunner
			if producerName == "Go" {
				producer = goRunner
			}
			for _, args := range [][]string{{"init-pki"}, {"build-ca", "nopass"}, {"build-client-full", "alice", "nopass"}} {
				out, err := producer.run(args...)
				require.NoError(t, err, "%v\n%s", args, out)
			}
			certificate := parseCertificatePEM(t, mustReadFile(t, filepath.Join(dir, "issued", "alice.crt")))
			serial := strings.ToLower(certificate.SerialNumber.Text(16))
			goRunner.env = append(goRunner.env, "EASYRSA_BATCH=")
			easyRunner.env = append(easyRunner.env, "EASYRSA_BATCH=")

			easyResult := runReadOnlyE2ECommand(t, easyRunner, "check-serial", serial)
			require.NoError(t, easyResult.err, easyResult.combinedOutput())
			goResult := runReadOnlyE2ECommand(t, goRunner, "check-serial", serial)
			require.NoError(t, goResult.err, goResult.combinedOutput())
			assertOccupiedSerialOutput(t, easyResult.stdout, certificate.SerialNumber.Text(16))
			assertOccupiedSerialOutput(t, goResult.stdout, certificate.SerialNumber.Text(16))
		})
	}
}

func TestE2E_DisplayDNParity(t *testing.T) {
	goRunner, easyRunner, goDir, easyDir := setupUtilityParity(t)
	for _, tt := range []struct {
		format string
		path   string
	}{
		{format: "x509", path: filepath.Join(easyDir, "issued", "alice.crt")},
		{format: "req", path: filepath.Join(easyDir, "reqs", "alice.req")},
		{format: "x509", path: filepath.Join(goDir, "issued", "alice.crt")},
		{format: "req", path: filepath.Join(goDir, "reqs", "alice.req")},
	} {
		easyResult := runReadOnlyE2ECommandAcrossTrees(t, easyRunner, []string{easyDir, goDir}, "display-dn", tt.format, tt.path)
		require.NoError(t, easyResult.err, easyResult.combinedOutput())
		goResult := runReadOnlyE2ECommandAcrossTrees(t, goRunner, []string{easyDir, goDir}, "display-dn", tt.format, tt.path)
		require.NoError(t, goResult.err, goResult.combinedOutput())
		require.Equal(t, normalizeDNOutput(t, easyResult.stdout), normalizeDNOutput(t, goResult.stdout))
	}
}

func TestE2E_RandParity(t *testing.T) {
	goRunner, easyRunner, _, _ := newParityRunners(t, nil, nil)
	easyResult := easyRunner.runCommand("rand", "16")
	require.NoError(t, easyResult.err, easyResult.combinedOutput())
	goResult := goRunner.runCommand("rand", "16")
	require.NoError(t, goResult.err, goResult.combinedOutput())
	pattern := regexp.MustCompile(`^[0-9a-f]{32}\n$`)
	require.Regexp(t, pattern, easyResult.stdout)
	require.Regexp(t, pattern, goResult.stdout)
	require.Empty(t, easyResult.stderr)
	require.Empty(t, goResult.stderr)
}

func setupUtilityParity(t *testing.T) (binaryRunner, binaryRunner, string, string) {
	t.Helper()
	baseEnv := []string{
		"EASYRSA_NO_PASS=1",
		"EASYRSA_DN=org",
		"EASYRSA_REQ_COUNTRY=PL",
		"EASYRSA_REQ_PROVINCE=Mazovia",
		"EASYRSA_REQ_CITY=Warsaw",
		"EASYRSA_REQ_ORG=Example Org",
		"EASYRSA_REQ_OU=VPN",
		"EASYRSA_REQ_EMAIL=subject@example.test",
		"EASYRSA_REQ_SERIAL=SUBJECT-42",
	}
	goRunner, easyRunner, goDir, easyDir := newParityRunners(t, baseEnv, nil)
	steps := [][]string{
		{"init-pki"},
		{"build-ca"},
		{"--san=DNS:alice.example.test", "--san=IP:192.0.2.10", "--san=email:san@example.test", "build-client-full", "alice"},
		{"build-server-full", "server"},
		{"build-serverClient-full", "dual"},
	}
	for _, args := range steps {
		out, err := easyRunner.run(args...)
		require.NoError(t, err, "easyrsa %v\n%s", args, out)
		out, err = goRunner.run(args...)
		require.NoError(t, err, "go-easyrsa %v\n%s", args, out)
	}
	return goRunner, easyRunner, goDir, easyDir
}

func runReadOnlyE2ECommand(t *testing.T, runner binaryRunner, args ...string) commandResult {
	t.Helper()
	return runReadOnlyE2ECommandAcrossTrees(t, runner, []string{runner.pkiDir}, args...)
}

func runReadOnlyE2ECommandAcrossTrees(t *testing.T, runner binaryRunner, roots []string, args ...string) commandResult {
	t.Helper()
	before := make(map[string]map[string]e2eTreeEntry)
	for _, root := range roots {
		if _, seen := before[root]; !seen {
			before[root] = snapshotE2ETree(t, root)
		}
	}
	result := runner.runCommand(args...)
	for root, snapshot := range before {
		require.Equal(t, snapshot, snapshotE2ETree(t, root), "%v changed %s", args, root)
	}
	return result
}

func requestPublicKeyOutput(request requestMeta) string {
	switch request.PublicKeyAlgo {
	case "rsa":
		return "RSA-" + request.PublicKeyInfo
	case "ecdsa":
		return "ECDSA-" + request.PublicKeyInfo
	case "ed25519":
		return "Ed25519"
	default:
		return request.PublicKeyAlgo + "-" + request.PublicKeyInfo
	}
}

func assertRequestOutputContains(t *testing.T, output string, request requestMeta) {
	t.Helper()
	values := []string{request.CN}
	values = append(values, request.Country...)
	values = append(values, request.Province...)
	values = append(values, request.Locality...)
	values = append(values, request.Organizations...)
	values = append(values, request.OrgUnits...)
	values = append(values, request.SubjectEmails...)
	values = append(values, request.DNS...)
	values = append(values, request.IPs...)
	values = append(values, request.Emails...)
	if request.SubjectSerial != "" {
		values = append(values, request.SubjectSerial)
	}
	for _, value := range values {
		require.Contains(t, output, value)
	}
}

var ekuOutputPattern = regexp.MustCompile(`(?m)'?(serverClient|codeSigning|client|server|undefined)'?\s*$`)

func extractEKULabel(t *testing.T, output string) string {
	t.Helper()
	match := ekuOutputPattern.FindStringSubmatch(output)
	require.Len(t, match, 2, output)
	return match[1]
}

func assertOccupiedSerialOutput(t *testing.T, output, serial string) {
	t.Helper()
	require.Contains(t, strings.ToUpper(output), strings.ToUpper(serial))
	upper := strings.ToUpper(output)
	require.True(t, strings.Contains(upper, "STATUS=V") || strings.Contains(upper, "VALID (V)"), output)
}

func normalizeDNOutput(t *testing.T, output string) []string {
	t.Helper()
	var attributes []string
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "subject" && value == "" {
			continue
		}
		attributes = append(attributes, key+"="+value)
	}
	require.NotEmpty(t, attributes, output)
	return attributes
}

type e2eTreeEntry struct {
	Mode fs.FileMode
	Data string
	Link string
}

func snapshotE2ETree(t *testing.T, root string) map[string]e2eTreeEntry {
	t.Helper()
	result := make(map[string]e2eTreeEntry)
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
		item := e2eTreeEntry{Mode: info.Mode()}
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
