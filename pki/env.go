package pki

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"strings"
)

var emailAddressOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// LoadConfigFromEnv overlays EASYRSA_* environment variables onto base.
//
// The function is intentionally non-failing: only recognized, parseable values
// override base; invalid values are ignored so callers can safely use it in
// library code without introducing a new error path.
func LoadConfigFromEnv(base Config) Config {
	cfg := base

	if value, ok := os.LookupEnv("EASYRSA_ALGO"); ok {
		if algo, ok := parseEasyRSAAlgo(strings.TrimSpace(value)); ok {
			cfg.KeyAlgo = algo
			if algo == AlgoECDSA && cfg.Curve == nil {
				cfg.Curve = elliptic.P384()
			}
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_KEY_SIZE"); ok {
		if parsed, ok := parseEnvInt(value); ok && parsed > 0 {
			cfg.KeySize = parsed
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_CURVE"); ok {
		if curve, ok := parseEasyRSACurve(strings.TrimSpace(value)); ok {
			cfg.Curve = curve
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_CA_EXPIRE"); ok {
		if parsed, ok := parseEnvInt(value); ok && parsed > 0 {
			cfg.CADays = parsed
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_CERT_EXPIRE"); ok {
		if parsed, ok := parseEnvInt(value); ok && parsed > 0 {
			cfg.DefaultDays = parsed
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_CRL_DAYS"); ok {
		if parsed, ok := parseEnvInt(value); ok && parsed > 0 {
			cfg.CRLDays = parsed
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_PRE_EXPIRY_WINDOW"); ok {
		if parsed, ok := parseEnvInt(value); ok && parsed >= 0 {
			cfg.PreExpiryDays = parsed
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_DN"); ok {
		if mode, ok := parseEnvDNMode(value); ok {
			cfg.DNMode = mode
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_NO_PASS"); ok {
		if parsed, ok := parseEnvBoolish(value); ok {
			cfg.NoPass = parsed
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_PASSIN"); ok {
		if pass, ok := parsePassEnv(value); ok {
			cfg.CAPassphrase = pass
			cfg.KeyPassphrase = pass
		}
	}
	if value, ok := os.LookupEnv("EASYRSA_RAND_SN"); ok {
		if random, ok := parseEnvBoolish(value); ok {
			cfg.SequentialSerial = !random
		}
	}

	cfg.SubjTemplate = applySubjectEnv(cfg.SubjTemplate)
	return cfg
}

func applySubjectEnv(base pkix.Name) pkix.Name {
	out := cloneName(base)

	if value, ok := os.LookupEnv("EASYRSA_REQ_COUNTRY"); ok {
		out.Country = singleValue(value)
	}
	if value, ok := os.LookupEnv("EASYRSA_REQ_PROVINCE"); ok {
		out.Province = singleValue(value)
	}
	if value, ok := os.LookupEnv("EASYRSA_REQ_CITY"); ok {
		out.Locality = singleValue(value)
	}
	if value, ok := os.LookupEnv("EASYRSA_REQ_ORG"); ok {
		out.Organization = singleValue(value)
	}
	if value, ok := os.LookupEnv("EASYRSA_REQ_OU"); ok {
		out.OrganizationalUnit = singleValue(value)
	}
	if value, ok := os.LookupEnv("EASYRSA_REQ_EMAIL"); ok {
		out = setEmailAddress(out, strings.TrimSpace(value))
	}
	return out
}

func cloneName(in pkix.Name) pkix.Name {
	out := in
	out.Country = append([]string(nil), in.Country...)
	out.Organization = append([]string(nil), in.Organization...)
	out.OrganizationalUnit = append([]string(nil), in.OrganizationalUnit...)
	out.Locality = append([]string(nil), in.Locality...)
	out.Province = append([]string(nil), in.Province...)
	out.StreetAddress = append([]string(nil), in.StreetAddress...)
	out.PostalCode = append([]string(nil), in.PostalCode...)
	out.Names = append([]pkix.AttributeTypeAndValue(nil), in.Names...)
	out.ExtraNames = append([]pkix.AttributeTypeAndValue(nil), in.ExtraNames...)
	return out
}

func singleValue(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return []string{trimmed}
}

func setEmailAddress(name pkix.Name, email string) pkix.Name {
	filtered := name.ExtraNames[:0]
	for _, attr := range name.ExtraNames {
		if !attr.Type.Equal(emailAddressOID) {
			filtered = append(filtered, attr)
		}
	}
	name.ExtraNames = filtered
	if email == "" {
		return name
	}
	name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: emailAddressOID, Value: email})
	return name
}
