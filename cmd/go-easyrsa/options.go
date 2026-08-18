package main

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/pki"
)

func buildCommonOptions(opts *cliOptions, cfg pki.Config, name string, scope commandScope, certType *cert.CertType, cmdOpts map[string]bool) ([]pki.Option, error) {
	var out []pki.Option

	if err := validateUnsupportedResultAffectingEnv(); err != nil {
		return nil, err
	}

	notBefore, notAfter, err := resolveValidity(opts)
	if err != nil {
		return nil, err
	}
	if !notBefore.IsZero() {
		out = append(out, pki.WithNotBefore(notBefore))
	}
	if !notAfter.IsZero() {
		out = append(out, pki.WithNotAfter(notAfter))
	}

	if opts.noPass || cmdOpts["nopass"] {
		out = append(out, pki.WithNoPass())
	} else if opts.passOut != "" && scope != commandScopeRenew {
		out = append(out, pki.WithPassphrase(parsePassEnv(opts.passOut)))
	}

	if subject, hasSubject := subjectFromCLI(opts); hasSubject {
		out = append(out, pki.WithSubject(subject))
	}
	if opts.reqSerial != "" && cfg.DNMode == pki.DNModeOrg {
		out = append(out, pki.WithSubjectSerial(strings.TrimSpace(opts.reqSerial)))
	}

	if scope == commandScopeSign && opts.newSubject != "" {
		if !cmdOpts["newsubj"] {
			return nil, errors.New("--new-subject requires command option 'newsubj'")
		}
		subj, err := parseSubjectString(opts.newSubject)
		if err != nil {
			return nil, err
		}
		out = append(out, pki.WithSubjectOverride(subj))
	}

	if scope == commandScopeSign || scope == commandScopeBuildFull {
		if opts.copyExt || scope == commandScopeBuildFull {
			out = append(out, pki.WithCopyCSRExtensions())
		}
	}

	if scope == commandScopeCA || (scope == commandScopeSign && certType != nil && *certType == cert.CertTypeCA) {
		if opts.subcaLen >= 0 || cmdOpts["subca"] {
			pathLen := 0
			if opts.subcaLen >= 0 {
				pathLen = opts.subcaLen
			}
			out = append(out, pki.WithSubCAPathLen(pathLen))
		}
	}

	if scope == commandScopeCSR || scope == commandScopeSign || scope == commandScopeBuildFull {
		dnsNames, ips, emails, err := resolveSANs(opts, name)
		if err != nil {
			return nil, err
		}
		if len(dnsNames) > 0 {
			out = append(out, pki.WithDNSNames(dnsNames...))
		}
		if len(ips) > 0 {
			out = append(out, pki.WithIPAddresses(ips...))
		}
		if len(emails) > 0 {
			out = append(out, pki.WithEmailAddresses(emails...))
		}
	}

	return out, nil
}

func resolveValidity(opts *cliOptions) (time.Time, time.Time, error) {
	var notBefore time.Time
	var notAfter time.Time
	var err error
	if opts.startDate != "" {
		notBefore, err = parseEasyRSATime(opts.startDate)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	if opts.endDate != "" {
		notAfter, err = parseEasyRSATime(opts.endDate)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	if opts.days > 0 && notAfter.IsZero() {
		base := time.Now().UTC()
		if !notBefore.IsZero() {
			base = notBefore
		}
		notAfter = base.AddDate(0, 0, opts.days)
	}
	return notBefore, notAfter, nil
}

func subjectFromCLI(opts *cliOptions) (pkix.Name, bool) {
	var subj pkix.Name
	var has bool
	if trimmed := strings.TrimSpace(opts.reqCN); trimmed != "" {
		subj.CommonName = trimmed
		has = true
	}
	if trimmed := strings.TrimSpace(opts.reqC); trimmed != "" {
		subj.Country = []string{trimmed}
		has = true
	}
	if trimmed := strings.TrimSpace(opts.reqST); trimmed != "" {
		subj.Province = []string{trimmed}
		has = true
	}
	if trimmed := strings.TrimSpace(opts.reqCity); trimmed != "" {
		subj.Locality = []string{trimmed}
		has = true
	}
	if trimmed := strings.TrimSpace(opts.reqOrg); trimmed != "" {
		subj.Organization = []string{trimmed}
		has = true
	}
	if trimmed := strings.TrimSpace(opts.reqOU); trimmed != "" {
		subj.OrganizationalUnit = []string{trimmed}
		has = true
	}
	if trimmed := strings.TrimSpace(opts.reqEmail); trimmed != "" {
		subj.ExtraNames = append(subj.ExtraNames, pkix.AttributeTypeAndValue{Type: emailAddressOID, Value: trimmed})
		has = true
	}
	return subj, has
}

func resolveSANs(opts *cliOptions, name string) ([]string, []net.IP, []string, error) {
	var entries []string
	if envSAN := strings.TrimSpace(os.Getenv("EASYRSA_SAN")); envSAN != "" {
		entries = append(entries, envSAN)
	}
	entries = append(entries, opts.sans...)
	entries = append(entries, opts.subjectAltNames...)
	if len(entries) == 0 && opts.autoSAN {
		cn := strings.TrimSpace(opts.reqCN)
		if cn == "" {
			cn = name
		}
		if ip := net.ParseIP(cn); ip != nil {
			entries = append(entries, "IP:"+ip.String())
		} else if cn != "" {
			entries = append(entries, "DNS:"+cn)
		}
	}
	return parseSANEntries(entries)
}

func optionalArg(args []string, idx int) string {
	if idx >= 0 && idx < len(args) {
		return args[idx]
	}
	return ""
}

func validateUnsupportedResultAffectingEnv() error {
	if !strictEnvParityEnabled() {
		return nil
	}
	for _, key := range []string{"EASYRSA_DIGEST", "EASYRSA_NS_COMMENT", "EASYRSA_EXTRA_EXTS", "EASYRSA_ALIAS_DAYS"} {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return fmt.Errorf("go-easyrsa: %s is not implemented yet (set GO_EASYRSA_STRICT_ENV_PARITY=0 to ignore unsupported env)", key)
		}
	}
	for _, key := range []string{"EASYRSA_BC_CRIT", "EASYRSA_KU_CRIT", "EASYRSA_EKU_CRIT", "EASYRSA_SAN_CRIT", "EASYRSA_NS_SUPPORT"} {
		if unsupportedBoolishEnvRequested(key) {
			return fmt.Errorf("go-easyrsa: %s is not implemented yet (set GO_EASYRSA_STRICT_ENV_PARITY=0 to ignore unsupported env)", key)
		}
	}
	return nil
}

func strictEnvParityEnabled() bool {
	for _, key := range []string{"GO_EASYRSA_STRICT_ENV_PARITY", "STRICT_ENV_PARITY"} {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		if parsed, ok := parseBoolish(value); ok {
			return parsed
		}
		return true
	}
	return true
}

func unsupportedBoolishEnvRequested(key string) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return false
	}
	if parsed, ok := parseBoolish(value); ok {
		return parsed
	}
	return true
}
