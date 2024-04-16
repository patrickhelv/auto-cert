package cert

// ServerCertificate holds details for a server certificate.
type ServerCertificate struct {
	Type        string
	CertFileName string
	KeyFileName  string
}

func (s ServerCertificate) TypeName() string {
	return s.Type
}

func (s ServerCertificate) FileNames() (certName, keyName string) {
	return s.CertFileName, s.KeyFileName
}

