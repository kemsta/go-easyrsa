package main

import (
	"fmt"
	"time"
)

func parseEasyRSATime(value string) (time.Time, error) {
	trimmed := value
	if trimmed == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse("20060102150405Z", trimmed); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("060102150405Z", trimmed); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q: expected [YY]YYMMDDhhmmssZ", value)
}
