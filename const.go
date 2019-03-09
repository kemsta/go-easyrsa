package easyrsa

const (
	PEMCertificateBlock   string = "CERTIFICATE"     // pem block header for x509.Certificate
	PEMRSAPrivateKeyBlock        = "RSA PRIVATE KEY" // pem block header for rsa.PrivateKey
	PEMx509CRLBlock              = "X509 CRL"        // pem block header for CRL
	CertFileExtension            = ".crt"            // pertificate file extension
	DefaultKeySizeBytes   int    = 2048              // pefault key size in bytes
	DefaultExpireYears           = 99                // pefault expire time for certs
)
