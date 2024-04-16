package cert

// Certificate represents a common interface for all certificate types.
type Certificate interface {
	TypeName() string
	FileNames() (certName, keyName string)
}