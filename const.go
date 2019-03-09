package easyrsa

const (
	PEMCertificateBlock   string = "CERTIFICATE"     // Pem block header for x509.Certificate
	PEMRSAPrivateKeyBlock        = "RSA PRIVATE KEY" // Pem block header for rsa.PrivateKey
	PEMx509CRLBlock              = "X509 CRL"        // Pem block header for CRL
	CertFileExtension            = ".crt"            // Certificate file extension
	DefaultKeySizeBytes   int    = 2048              // Default key size in bytes
	DefaultExpireYears           = 99                // Default expire time for certs
)
