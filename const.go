package pki

const (
	PEMCertificateBlock   string = "CERTIFICATE"
	PEMRSAPrivateKeyBlock        = "RSA PRIVATE KEY"
	PEMx509CRLBlock              = "X509 CRL"
	PEMCSRBlock                  = "CERTIFICATE REQUEST"
	DefaultKeySizeBytes   int    = 2048
	DefaultExpireYears           = 99
)
