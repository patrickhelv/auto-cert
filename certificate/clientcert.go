package cert

// ClientCertificate holds details for a client certificate.
type ClientCertificate struct {
	Type        string
	CertFileName string
	KeyFileName  string
}

func (c ClientCertificate) TypeName() string {
	return c.Type
}

func (c ClientCertificate) FileNames() (certName, keyName string) {
	return c.CertFileName, c.KeyFileName
}