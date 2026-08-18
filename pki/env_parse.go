package pki

import (
	"crypto/elliptic"
	"strconv"
	"strings"
)

func parseEnvInt(value string) (int, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func parseEnvBoolish(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y":
		return true, true
	case "0", "false", "no", "off", "n":
		return false, true
	default:
		return false, false
	}
}

func parsePassEnv(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	if rest, ok := strings.CutPrefix(value, "pass:"); ok {
		return rest, true
	}
	return value, true
}

func parseEasyRSAAlgo(value string) (KeyAlgo, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "rsa":
		return AlgoRSA, value != ""
	case "ec", "ecdsa":
		return AlgoECDSA, true
	case "ed", "ed25519":
		return AlgoEd25519, true
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

func parseEnvDNMode(value string) (DNMode, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(DNModeCNOnly):
		return DNModeCNOnly, true
	case string(DNModeOrg):
		return DNModeOrg, true
	default:
		return "", false
	}
}
