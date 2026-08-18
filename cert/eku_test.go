package cert_test

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certpkg "github.com/kemsta/go-easyrsa/v2/cert"
)

func TestClassifyEKU(t *testing.T) {
	tests := []struct {
		name  string
		usage []x509.ExtKeyUsage
		want  certpkg.EKUType
	}{
		{name: "client", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, want: certpkg.EKUClient},
		{name: "server", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, want: certpkg.EKUServer},
		{name: "server client", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, want: certpkg.EKUServerClient},
		{name: "code signing", usage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, want: certpkg.EKUCodeSigning},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := certpkg.ClassifyEKU(&x509.Certificate{ExtKeyUsage: tt.usage})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClassifyEKUUndefined(t *testing.T) {
	got, err := certpkg.ClassifyEKU(&x509.Certificate{})
	assert.Equal(t, certpkg.EKUUndefined, got)
	require.Error(t, err)
	assert.ErrorIs(t, err, certpkg.ErrUnknownEKU)
}

func TestClassifyEKUUnknown(t *testing.T) {
	tests := []struct {
		name        string
		usage       []x509.ExtKeyUsage
		unknown     []asn1.ObjectIdentifier
		wantMessage string
	}{
		{
			name:        "unsupported known usage",
			usage:       []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			wantMessage: "1.3.6.1.5.5.7.3.4",
		},
		{
			name:        "known and unsupported mix",
			usage:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
			wantMessage: "1.3.6.1.5.5.7.3.2",
		},
		{
			name:        "server client reversed",
			usage:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			wantMessage: "1.3.6.1.5.5.7.3.1",
		},
		{
			name:        "duplicate client",
			usage:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth},
			wantMessage: "1.3.6.1.5.5.7.3.2",
		},
		{
			name:        "unknown oid",
			unknown:     []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}},
			wantMessage: "1.2.3.4.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := certpkg.ClassifyEKU(&x509.Certificate{ExtKeyUsage: tt.usage, UnknownExtKeyUsage: tt.unknown})
			assert.Equal(t, certpkg.EKUUnknown, got)
			require.Error(t, err)
			assert.ErrorIs(t, err, certpkg.ErrUnknownEKU)
			assert.Contains(t, err.Error(), tt.wantMessage)
		})
	}
}

func TestClassifyEKUNilCertificate(t *testing.T) {
	got, err := certpkg.ClassifyEKU(nil)
	assert.Empty(t, got)
	require.Error(t, err)
	assert.False(t, errors.Is(err, certpkg.ErrUnknownEKU))
}
