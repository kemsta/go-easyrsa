package easyrsa

const (
	PEMCertificateBlock   string = "CERTIFICATE"
	PEMRSAPrivateKeyBlock        = "RSA PRIVATE KEY"
	PEMx509CRLBlock              = "X509 CRL"
	DefaultKeySizeBytes   int    = 2048
	DefaultExpireYears           = 99
)
