package cert

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// EKUType is the Easy-RSA certificate type derived from Extended Key Usage.
type EKUType string

const (
	EKUClient       EKUType = "client"
	EKUServer       EKUType = "server"
	EKUServerClient EKUType = "serverClient"
	EKUCodeSigning  EKUType = "codeSigning"
	EKUUndefined    EKUType = "undefined"
	EKUUnknown      EKUType = "unknown"
)

// ErrUnknownEKU reports an empty or unsupported Extended Key Usage combination.
var ErrUnknownEKU = errors.New("cert: unknown extended key usage")

// ClassifyEKU maps a certificate's Extended Key Usage to Easy-RSA's labels.
// Empty and unsupported combinations return a useful label together with
// ErrUnknownEKU so callers can display the classification before failing.
func ClassifyEKU(certificate *x509.Certificate) (EKUType, error) {
	if certificate == nil {
		return "", errors.New("cert: nil certificate")
	}

	usages := certificate.ExtKeyUsage
	if len(usages) == 0 && len(certificate.UnknownExtKeyUsage) == 0 {
		return EKUUndefined, fmt.Errorf("%w: %s", ErrUnknownEKU, EKUUndefined)
	}
	if len(certificate.UnknownExtKeyUsage) == 0 {
		switch {
		case len(usages) == 1 && usages[0] == x509.ExtKeyUsageClientAuth:
			return EKUClient, nil
		case len(usages) == 1 && usages[0] == x509.ExtKeyUsageServerAuth:
			return EKUServer, nil
		case len(usages) == 2 && usages[0] == x509.ExtKeyUsageServerAuth && usages[1] == x509.ExtKeyUsageClientAuth:
			return EKUServerClient, nil
		case len(usages) == 1 && usages[0] == x509.ExtKeyUsageCodeSigning:
			return EKUCodeSigning, nil
		}
	}

	return EKUUnknown, fmt.Errorf("%w: %s", ErrUnknownEKU, strings.Join(ekuOIDStrings(usages, certificate.UnknownExtKeyUsage), ","))
}

func ekuOIDStrings(known []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) []string {
	result := make([]string, 0, len(known)+len(unknown))
	for _, usage := range known {
		result = append(result, ekuOIDString(usage))
	}
	for _, oid := range unknown {
		result = append(result, oid.String())
	}
	sort.Strings(result)
	return result
}

func ekuOIDString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "2.5.29.37.0"
	case x509.ExtKeyUsageServerAuth:
		return "1.3.6.1.5.5.7.3.1"
	case x509.ExtKeyUsageClientAuth:
		return "1.3.6.1.5.5.7.3.2"
	case x509.ExtKeyUsageCodeSigning:
		return "1.3.6.1.5.5.7.3.3"
	case x509.ExtKeyUsageEmailProtection:
		return "1.3.6.1.5.5.7.3.4"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "1.3.6.1.5.5.7.3.5"
	case x509.ExtKeyUsageIPSECTunnel:
		return "1.3.6.1.5.5.7.3.6"
	case x509.ExtKeyUsageIPSECUser:
		return "1.3.6.1.5.5.7.3.7"
	case x509.ExtKeyUsageTimeStamping:
		return "1.3.6.1.5.5.7.3.8"
	case x509.ExtKeyUsageOCSPSigning:
		return "1.3.6.1.5.5.7.3.9"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "1.3.6.1.4.1.311.10.3.3"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "2.16.840.1.113730.4.1"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "1.3.6.1.4.1.311.2.1.22"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "1.3.6.1.4.1.311.61.1.1"
	default:
		return fmt.Sprintf("ext-key-usage-%d", usage)
	}
}
