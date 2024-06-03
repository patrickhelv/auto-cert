package cert

// Certificate is an interface for handling certificates.
type Certificate interface {
	TypeName() string
	FileNames() (certName, keyName string)
	CommonName() string
	SubjectAltName() string
}