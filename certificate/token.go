package cert

// Token holds details for a token.
type Token struct {
	Type        string
	TokenFileName string
	KeyFileName  string
}

func (t Token) TypeName() string {
	return t.Type
}

func (t Token) FileNames() (tokenName, keyName string) {
	return t.TokenFileName, t.KeyFileName
}