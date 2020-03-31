package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestCN(t *testing.T) {
	type args struct {
		cn string
	}
	tests := []struct {
		name string
		args args
		want *x509.Certificate
	}{
		{
			name: "change cn",
			args: args{
				cn: "changed",
			},
			want: &x509.Certificate{Subject: pkix.Name{CommonName: "changed"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			if CN(tt.args.cn)(cert); !reflect.DeepEqual(cert, tt.want) {
				t.Errorf("CN() = %v, want %v", cert, tt.want)
			}
		})
	}
}

func TestDNSNames(t *testing.T) {
	type args struct {
		names []string
	}
	tests := []struct {
		name string
		args args
		want *x509.Certificate
	}{
		{
			name: "changed",
			args: args{
				names: []string{"first", "second"},
			},
			want: &x509.Certificate{DNSNames: []string{"first", "second"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			if DNSNames(tt.args.names)(cert); !reflect.DeepEqual(cert, tt.want) {
				t.Errorf("DNSNames() = %v, want %v", cert, tt.want)
			}
		})
	}
}

func TestExcludedDNSDomains(t *testing.T) {
	type args struct {
		names []string
	}
	tests := []struct {
		name string
		args args
		want *x509.Certificate
	}{
		{
			name: "changed",
			args: args{
				names: []string{"first", "second"},
			},
			want: &x509.Certificate{ExcludedDNSDomains: []string{"first", "second"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			if ExcludedDNSDomains(tt.args.names)(cert); !reflect.DeepEqual(cert, tt.want) {
				t.Errorf("ExcludedDNSDomains() = %v, want %v", cert, tt.want)
			}
		})
	}
}

func TestIPAddresses(t *testing.T) {
	type args struct {
		ips []net.IP
	}
	tests := []struct {
		name string
		args args
		want *x509.Certificate
	}{
		{
			name: "changed",
			args: args{
				ips: []net.IP{{127, 0, 0, 1}},
			},
			want: &x509.Certificate{IPAddresses: []net.IP{{127, 0, 0, 1}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			if IPAddresses(tt.args.ips)(cert); !reflect.DeepEqual(cert, tt.want) {
				t.Errorf("IPAddresses() = %v, want %v", cert, tt.want)
			}
		})
	}
}

func TestServer(t *testing.T) {
	want := &x509.Certificate{}
	want.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment
	want.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	val, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}) // setting nsCertType to Server Type
	want.ExtraExtensions = []pkix.Extension{}
	want.ExtraExtensions = append(want.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}, Value: val})
	tests := []struct {
		name string
		want *x509.Certificate
	}{
		{
			name: "changed",
			want: want,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			if Server()(cert); !reflect.DeepEqual(cert, tt.want) {
				t.Errorf("Server() = %v, want %v", cert, tt.want)
			}
		})
	}
}

func TestNotAfter(t *testing.T) {
	type args struct {
		time time.Time
	}
	tests := []struct {
		name string
		args args
		want *x509.Certificate
	}{
		{
			name: "changed",
			args: args{
				time: time.Unix(100000, 0),
			},
			want: &x509.Certificate{NotAfter: time.Unix(100000, 0)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{}
			if NotAfter(tt.args.time)(cert); !reflect.DeepEqual(cert, tt.want) {
				t.Errorf("NotAfter() = %v, want %v", cert, tt.want)
			}
		})
	}
}
