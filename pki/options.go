package pki

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"time"
)

// Option configures a key+certificate generation operation.
type Option func(*options)

type options struct {
	// Key generation
	keyAlgo KeyAlgo
	keySize int
	curve   elliptic.Curve

	// Key protection (per-operation overrides of Config defaults)
	noPass     *bool  // nil = use Config.NoPass
	passphrase string // encrypts the generated private key (PKCS8 encrypted PEM)

	// Certificate validity
	notBefore time.Time
	notAfter  time.Time

	// Subject override (merged with PKI config default)
	subject       *pkix.Name
	subjectSerial string // certificate Subject serialNumber field (distinct from x509 serial)

	// Subject Alternative Names
	dnsNames    []string
	ipAddresses []net.IP
	emailAddrs  []string

	// SAN behaviour
	autoSAN     bool // derive SAN from CN (DNS or IP based on format)
	sanCritical bool

	// Extension criticality overrides
	bcCritical  bool // basicConstraints
	kuCritical  bool // keyUsage
	ekuCritical bool // extendedKeyUsage

	// CSR signing behaviour (used by SignReq)
	copyCSRExtensions bool       // copy extensions from CSR (e.g. SANs)
	subjectOverride   *pkix.Name // replace subject DN when signing
	preserveDN        bool       // preserve CSR DN field order instead of CA order

	// Sub-CA path length constraint (used by BuildCA for intermediate CAs)
	subCAPathLen *int // nil = no constraint; 0 = no further intermediates

	// PKCS#12 export
	p12FriendlyName string

	// Escape hatch: applied last, after all named options
	certModifiers []func(*x509.Certificate)
}

// WithKeyAlgo sets the key algorithm for this operation.
func WithKeyAlgo(algo KeyAlgo) Option {
	return func(o *options) { o.keyAlgo = algo }
}

// WithKeySize sets the RSA key size in bits.
func WithKeySize(bits int) Option {
	return func(o *options) { o.keySize = bits }
}

// WithCurve sets the elliptic curve for ECDSA key generation.
func WithCurve(c elliptic.Curve) Option {
	return func(o *options) { o.curve = c }
}

// WithPassphrase encrypts the generated private key with passphrase (PKCS8 encrypted PEM).
func WithPassphrase(passphrase string) Option {
	return func(o *options) { o.passphrase = passphrase }
}

// WithNoPass stores the key unencrypted, regardless of Config.NoPass.
func WithNoPass() Option {
	t := true
	return func(o *options) { o.noPass = &t }
}

// WithNotBefore sets the certificate NotBefore time.
func WithNotBefore(t time.Time) Option {
	return func(o *options) { o.notBefore = t }
}

// WithNotAfter sets the certificate NotAfter time.
func WithNotAfter(t time.Time) Option {
	return func(o *options) { o.notAfter = t }
}

// WithDays sets NotAfter to now + days.
func WithDays(days int) Option {
	return func(o *options) { o.notAfter = time.Now().AddDate(0, 0, days) }
}

// WithCN sets the certificate Common Name.
func WithCN(cn string) Option {
	return func(o *options) {
		if o.subject == nil {
			o.subject = &pkix.Name{}
		}
		o.subject.CommonName = cn
	}
}

// WithSubject sets the full subject distinguished name.
func WithSubject(name pkix.Name) Option {
	return func(o *options) { o.subject = &name }
}

// WithSubjectSerial sets the Subject serialNumber field (distinct from x509 serial).
func WithSubjectSerial(serial string) Option {
	return func(o *options) { o.subjectSerial = serial }
}

// WithAutoSAN derives a SAN from the CN automatically.
func WithAutoSAN() Option {
	return func(o *options) { o.autoSAN = true }
}

// WithDNSNames adds DNS SANs.
func WithDNSNames(names ...string) Option {
	return func(o *options) { o.dnsNames = append(o.dnsNames, names...) }
}

// WithIPAddresses adds IP SANs.
func WithIPAddresses(ips ...net.IP) Option {
	return func(o *options) { o.ipAddresses = append(o.ipAddresses, ips...) }
}

// WithEmailAddresses adds email SANs.
func WithEmailAddresses(addrs ...string) Option {
	return func(o *options) { o.emailAddrs = append(o.emailAddrs, addrs...) }
}

// WithSANCritical marks the SAN extension as critical.
func WithSANCritical() Option {
	return func(o *options) { o.sanCritical = true }
}

// WithBasicConstraintsCritical marks the basicConstraints extension as critical.
func WithBasicConstraintsCritical() Option {
	return func(o *options) { o.bcCritical = true }
}

// WithKeyUsageCritical marks the keyUsage extension as critical.
func WithKeyUsageCritical() Option {
	return func(o *options) { o.kuCritical = true }
}

// WithExtKeyUsageCritical marks the extendedKeyUsage extension as critical.
func WithExtKeyUsageCritical() Option {
	return func(o *options) { o.ekuCritical = true }
}

// WithCopyCSRExtensions copies extensions from the CSR when signing (including SANs).
func WithCopyCSRExtensions() Option {
	return func(o *options) { o.copyCSRExtensions = true }
}

// WithSubjectOverride replaces the subject DN when signing a CSR.
func WithSubjectOverride(name pkix.Name) Option {
	return func(o *options) { o.subjectOverride = &name }
}

// WithPreserveDN preserves CSR DN field order instead of using CA field order.
func WithPreserveDN() Option {
	return func(o *options) { o.preserveDN = true }
}

// WithSubCAPathLen sets the path length constraint for a sub-CA certificate.
// n=0 means no further intermediates are allowed.
func WithSubCAPathLen(n int) Option {
	return func(o *options) { o.subCAPathLen = &n }
}

// WithP12FriendlyName sets the friendly name for PKCS#12 export.
func WithP12FriendlyName(name string) Option {
	return func(o *options) { o.p12FriendlyName = name }
}

// WithCertModifier provides direct access to the x509.Certificate template
// for advanced cases not covered by named options.
// Applied after all named options; multiple modifiers run in order.
func WithCertModifier(fn func(*x509.Certificate)) Option {
	return func(o *options) { o.certModifiers = append(o.certModifiers, fn) }
}

// applyOptions applies all Option funcs to a new options struct and returns it.
func applyOptions(opts []Option) options {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	return o
}
