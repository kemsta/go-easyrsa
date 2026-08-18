package main

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kemsta/go-easyrsa/v2/pki"
)

var emailAddressOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

type cliOptions struct {
	pkiDir string

	days      int
	startDate string
	endDate   string

	algo    string
	curve   string
	keySize int

	dnMode    string
	reqCN     string
	reqC      string
	reqST     string
	reqCity   string
	reqOrg    string
	reqEmail  string
	reqOU     string
	reqSerial string

	noPass    bool
	noPassSet bool
	passIn    string
	passOut   string

	copyExt         bool
	autoSAN         bool
	sans            []string
	subjectAltNames []string
	newSubject      string
	subcaLen        int
	useFN           string
	preserveDN      bool
	rawCA           string
	batch           bool
}

type commandScope int

const (
	commandScopeCSR commandScope = iota
	commandScopeSign
	commandScopeBuildFull
	commandScopeRenew
	commandScopeCA
)

func defaultCLIOptions() cliOptions {
	opts := cliOptions{
		pkiDir:   envString("EASYRSA_PKI", "pki"),
		algo:     os.Getenv("EASYRSA_ALGO"),
		curve:    os.Getenv("EASYRSA_CURVE"),
		dnMode:   os.Getenv("EASYRSA_DN"),
		subcaLen: -1,

		startDate: os.Getenv("EASYRSA_START_DATE"),
		endDate:   os.Getenv("EASYRSA_END_DATE"),
		passIn:    os.Getenv("EASYRSA_PASSIN"),
		passOut:   os.Getenv("EASYRSA_PASSOUT"),

		reqCN:     os.Getenv("EASYRSA_REQ_CN"),
		reqC:      os.Getenv("EASYRSA_REQ_COUNTRY"),
		reqST:     os.Getenv("EASYRSA_REQ_PROVINCE"),
		reqCity:   os.Getenv("EASYRSA_REQ_CITY"),
		reqOrg:    os.Getenv("EASYRSA_REQ_ORG"),
		reqEmail:  os.Getenv("EASYRSA_REQ_EMAIL"),
		reqOU:     os.Getenv("EASYRSA_REQ_OU"),
		reqSerial: os.Getenv("EASYRSA_REQ_SERIAL"),

		newSubject: os.Getenv("EASYRSA_NEW_SUBJECT"),
		useFN:      os.Getenv("EASYRSA_P12_FR_NAME"),
		rawCA:      os.Getenv("EASYRSA_RAW_CA"),
	}
	if parsed, ok := parseInt(strings.TrimSpace(os.Getenv("EASYRSA_KEY_SIZE"))); ok {
		opts.keySize = parsed
	}
	if parsed, ok := parseInt(strings.TrimSpace(os.Getenv("EASYRSA_SUBCA_LEN"))); ok {
		opts.subcaLen = parsed
	}
	if parsed, ok := parseBoolish(strings.TrimSpace(os.Getenv("EASYRSA_NO_PASS"))); ok {
		opts.noPass = parsed
	}
	if parsed, ok := parseBoolish(strings.TrimSpace(os.Getenv("EASYRSA_CP_EXT"))); ok {
		opts.copyExt = parsed
	}
	if parsed, ok := parseBoolish(strings.TrimSpace(os.Getenv("EASYRSA_AUTO_SAN"))); ok {
		opts.autoSAN = parsed
	}
	if parsed, ok := parseBoolish(strings.TrimSpace(os.Getenv("EASYRSA_PRESERVE_DN"))); ok {
		opts.preserveDN = parsed
	}
	if parsed, ok := parseBoolish(strings.TrimSpace(os.Getenv("EASYRSA_BATCH"))); ok {
		opts.batch = parsed
	}
	return opts
}

func openPKI(opts *cliOptions, mutate func(*pki.Config)) (*pki.PKI, pki.Config, error) {
	cfg, err := buildConfig(opts)
	if err != nil {
		return nil, pki.Config{}, err
	}
	if mutate != nil {
		mutate(&cfg)
	}
	pk, err := pki.NewWithFS(opts.pkiDir, cfg)
	return pk, cfg, err
}

func buildConfig(opts *cliOptions) (pki.Config, error) {
	cfg := pki.LoadConfigFromEnv(pki.Config{SubjTemplate: easyRSADefaultSubject()})

	if opts.algo != "" {
		algo, ok := parseEasyRSAAlgo(opts.algo)
		if !ok {
			return pki.Config{}, fmt.Errorf("unknown algorithm %q", opts.algo)
		}
		cfg.KeyAlgo = algo
		if algo == pki.AlgoECDSA && cfg.Curve == nil {
			cfg.Curve = elliptic.P384()
		}
	}
	if opts.keySize > 0 {
		cfg.KeySize = opts.keySize
	}
	if opts.curve != "" {
		curve, ok := parseEasyRSACurve(opts.curve)
		if !ok {
			return pki.Config{}, fmt.Errorf("unknown curve %q", opts.curve)
		}
		cfg.Curve = curve
	}
	if opts.dnMode != "" {
		mode, ok := parseDNMode(opts.dnMode)
		if !ok {
			return pki.Config{}, fmt.Errorf("unknown DN mode %q", opts.dnMode)
		}
		cfg.DNMode = mode
	}
	if opts.noPassSet {
		cfg.NoPass = opts.noPass
	} else if opts.noPass {
		cfg.NoPass = true
	}
	if opts.passIn != "" {
		pass := parsePassEnv(opts.passIn)
		cfg.CAPassphrase = pass
		cfg.KeyPassphrase = pass
	}

	if opts.reqC != "" {
		cfg.SubjTemplate.Country = []string{strings.TrimSpace(opts.reqC)}
	}
	if opts.reqST != "" {
		cfg.SubjTemplate.Province = []string{strings.TrimSpace(opts.reqST)}
	}
	if opts.reqCity != "" {
		cfg.SubjTemplate.Locality = []string{strings.TrimSpace(opts.reqCity)}
	}
	if opts.reqOrg != "" {
		cfg.SubjTemplate.Organization = []string{strings.TrimSpace(opts.reqOrg)}
	}
	if opts.reqOU != "" {
		cfg.SubjTemplate.OrganizationalUnit = []string{strings.TrimSpace(opts.reqOU)}
	}
	if opts.reqEmail != "" {
		cfg.SubjTemplate = setEmailAddress(cfg.SubjTemplate, strings.TrimSpace(opts.reqEmail))
	}
	return cfg, nil
}

func easyRSADefaultSubject() pkix.Name {
	return setEmailAddress(pkix.Name{
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"Copyleft Certificate Co"},
		OrganizationalUnit: []string{"My Organizational Unit"},
	}, "me@example.net")
}

func setEmailAddress(name pkix.Name, email string) pkix.Name {
	filtered := name.ExtraNames[:0]
	for _, attr := range name.ExtraNames {
		if !attr.Type.Equal(emailAddressOID) {
			filtered = append(filtered, attr)
		}
	}
	name.ExtraNames = filtered
	if email != "" {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: emailAddressOID, Value: email})
	}
	return name
}

func parseDNMode(value string) (pki.DNMode, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(pki.DNModeCNOnly):
		return pki.DNModeCNOnly, true
	case string(pki.DNModeOrg):
		return pki.DNModeOrg, true
	default:
		return "", false
	}
}

func parseEasyRSAAlgo(value string) (pki.KeyAlgo, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "rsa":
		return pki.AlgoRSA, true
	case "ec", "ecdsa":
		return pki.AlgoECDSA, true
	case "ed", "ed25519":
		return pki.AlgoEd25519, true
	default:
		return "", false
	}
}

func parseEasyRSACurve(value string) (elliptic.Curve, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "prime256v1", "secp256r1", "p256":
		return elliptic.P256(), true
	case "secp384r1", "p384":
		return elliptic.P384(), true
	case "secp521r1", "p521":
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func parseInt(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func validateNumericEnv() error {
	for _, key := range []string{
		"EASYRSA_KEY_SIZE",
		"EASYRSA_CA_EXPIRE",
		"EASYRSA_CERT_EXPIRE",
		"EASYRSA_CRL_DAYS",
	} {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		parsed, ok := parseInt(value)
		if !ok || parsed <= 0 {
			return fmt.Errorf("go-easyrsa: %s must be a positive integer", key)
		}
	}
	for _, key := range []string{"EASYRSA_PRE_EXPIRY_WINDOW", "EASYRSA_SUBCA_LEN"} {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		parsed, ok := parseInt(value)
		if !ok || parsed < 0 {
			return fmt.Errorf("go-easyrsa: %s must be a non-negative integer", key)
		}
	}
	return nil
}

func parseBoolish(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y":
		return true, true
	case "0", "false", "no", "off", "n":
		return false, true
	default:
		return false, false
	}
}

func parsePassEnv(value string) string {
	if rest, ok := strings.CutPrefix(value, "pass:"); ok {
		return rest
	}
	return value
}
