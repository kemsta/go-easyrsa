package main

import (
	"fmt"
	"sort"
	"strings"
)

func parseCommandOpts(args []string, allowed ...string) (map[string]bool, error) {
	allowedSet := make(map[string]bool, len(allowed))
	for _, item := range allowed {
		allowedSet[strings.ToLower(strings.TrimSpace(item))] = true
	}
	out := make(map[string]bool, len(args))
	for _, arg := range args {
		token := strings.ToLower(strings.TrimSpace(arg))
		if token == "" {
			continue
		}
		if len(allowedSet) > 0 && !allowedSet[token] {
			var values []string
			for value := range allowedSet {
				values = append(values, value)
			}
			sort.Strings(values)
			return nil, fmt.Errorf("unknown command option %q (allowed: %s)", arg, strings.Join(values, ", "))
		}
		out[token] = true
	}
	return out, nil
}
