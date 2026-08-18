package main

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

func parseSubjectString(value string) (pkix.Name, error) {
	var subj pkix.Name
	for _, part := range strings.Split(strings.TrimSpace(value), "/") {
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return pkix.Name{}, fmt.Errorf("invalid subject component %q", part)
		}
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "CN":
			subj.CommonName = strings.TrimSpace(val)
		case "C":
			subj.Country = []string{strings.TrimSpace(val)}
		case "ST":
			subj.Province = []string{strings.TrimSpace(val)}
		case "L":
			subj.Locality = []string{strings.TrimSpace(val)}
		case "O":
			subj.Organization = []string{strings.TrimSpace(val)}
		case "OU":
			subj.OrganizationalUnit = []string{strings.TrimSpace(val)}
		case "SERIALNUMBER":
			subj.SerialNumber = strings.TrimSpace(val)
		case "EMAILADDRESS":
			subj.ExtraNames = append(subj.ExtraNames, pkix.AttributeTypeAndValue{Type: emailAddressOID, Value: strings.TrimSpace(val)})
		default:
			return pkix.Name{}, fmt.Errorf("unsupported subject attribute %q", key)
		}
	}
	return subj, nil
}
