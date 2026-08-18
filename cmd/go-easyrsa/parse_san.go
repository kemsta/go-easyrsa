package main

import (
	"fmt"
	"net"
	"strings"
)

func parseSANEntries(entries []string) ([]string, []net.IP, []string, error) {
	var dnsNames []string
	var ips []net.IP
	var emails []string
	for _, entry := range entries {
		for _, part := range strings.Split(entry, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kind, value, ok := strings.Cut(part, ":")
			if !ok {
				return nil, nil, nil, fmt.Errorf("invalid SAN %q", part)
			}
			switch strings.ToLower(strings.TrimSpace(kind)) {
			case "dns":
				dnsNames = append(dnsNames, strings.TrimSpace(value))
			case "ip":
				ip := net.ParseIP(strings.TrimSpace(value))
				if ip == nil {
					return nil, nil, nil, fmt.Errorf("invalid SAN IP %q", value)
				}
				ips = append(ips, ip)
			case "email":
				emails = append(emails, strings.TrimSpace(value))
			default:
				return nil, nil, nil, fmt.Errorf("unsupported SAN type %q", kind)
			}
		}
	}
	return dnsNames, ips, emails, nil
}
