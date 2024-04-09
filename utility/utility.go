package utility

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"crypto/x509"
	"crypto/ecdsa"
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
	"strings"
)

type CaCertification struct {
	Carcert string `yaml:"ca_cert"`
}

type ClientCertification struct {
	ClientCert string `yaml:"client_cert"`
}

type CaPKey struct {
	Cakey string `yaml:"ca_key"`
}

type ClientPKey struct {
	ClientKey string `yaml:"client_key"`
}

type TokenPKey struct {
	TokenKey string `yaml:"token_key"`
}

type Token struct {
	Token string `yaml:"token"`
}

// Reads a specified config files
// returns (nil, error) if the an error happens while reading
// returns (map[string]string, nil) if the reading of the file is successfull
func readConfigFile(filePath string) (map[string]string, error) {

	config := make(map[string]string)

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Iterate through each line in the file
	for scanner.Scan() {
		line := scanner.Text()

		// reading key-value pairs separated by '='
		parts := strings.Split(line, "=")
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			config[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}

func FetchConfigFile(configFile string) ([]string, error) {
	var CONFIG_VAULT_PATH = "VAULT_PATH"
	var CONFIG_VAULT_PASS = "VAULT_PASS"

	var result []string

	// retrieves the value from the configuration file
	configFileMap, err := readConfigFile(configFile)
	if configFileMap == nil {
		fmt.Printf("Error reading the configuration file, %s", err)
		return nil, err
	}

	if val, exists := configFileMap[CONFIG_VAULT_PATH]; exists {
		result = append(result, val)
	} else {
		return nil, err
	}

	if val, exists := configFileMap[CONFIG_VAULT_PASS]; exists {
		result = append(result, val)
	} else {
		return nil, err
	}

	return result, nil
}

// Function to encode private key to PEM format
func EncodeToPEMPK(privateKey *ecdsa.PrivateKey) string {
	pemType := "EC PRIVATE KEY"

	data, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Printf("Error marshalling ECDSA key to ASN.1 DER form: %v\n", err)
		return ""
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}

	var pemBuf bytes.Buffer
	err = pem.Encode(&pemBuf, pemBlock)
	if err != nil {
		fmt.Printf("Error encoding to PEM: %v\n", err)
		return ""
	}

	return pemBuf.String()
}

// Function to encode a public key to PEM format
func EncodeToPEMPubK(publicKey *ecdsa.PublicKey) string {
	pemType := "PUBLIC KEY"

	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Printf("Error marshalling ECDSA key to ASN.1 DER form: %v\n", err)
		return ""
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}

	var pemBuf bytes.Buffer
	err = pem.Encode(&pemBuf, pemBlock)
	if err != nil {
		fmt.Printf("Error encoding to PEM: %v\n", err)
		return ""
	}

	return pemBuf.String()
}

// Function to encode certificate or key bytes to PEM format
func EncodeToPEMCert(Bytes []byte) string {
	pemType := "CERTIFICATE"

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: Bytes,
	}

	var pemBuf bytes.Buffer
	err := pem.Encode(&pemBuf, pemBlock)
	if err != nil {
		fmt.Printf("Error encoding to PEM: %v\n", err)
		return ""
	}

	return pemBuf.String()
}

func DecodeYamlCertCa(filePath string) (CaCertification, error) {

	var cert CaCertification

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return cert, err
	}

	err = yaml.Unmarshal([]byte(data), &cert)
	if err != nil {
		fmt.Println(err)
		return cert, err
	}

	return cert, nil
}

func DecodeYamlClientCert(filePath string) (ClientCertification, error) {

	var cert ClientCertification

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return cert, err
	}

	err = yaml.Unmarshal([]byte(data), &cert)
	if err != nil {
		fmt.Println(err)
		return cert, err
	}

	return cert, nil
}

func DecodeYamlCaKey(filePath string) (CaPKey, error) {

	var key CaPKey

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return key, err
	}

	err = yaml.Unmarshal([]byte(data), &key)
	if err != nil {
		fmt.Println(err)
		return key, err
	}

	return key, nil
}

func DecodeYamlClientKey(filePath string) (ClientPKey, error) {

	var key ClientPKey

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return key, err
	}

	err = yaml.Unmarshal([]byte(data), &key)
	if err != nil {
		fmt.Println(err)
		return key, err
	}

	return key, nil
}

func DecodeYamlTokenKey(filePath string) (TokenPKey, error) {

	var key TokenPKey

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return key, err
	}

	err = yaml.Unmarshal([]byte(data), &key)
	if err != nil {
		fmt.Println(err)
		return key, err
	}

	return key, nil
}

func DecodeToken(filePath string) (Token, error) {

	var token Token

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return token, err
	}

	err = yaml.Unmarshal([]byte(data), &token)
	if err != nil {
		fmt.Println(err)
		return token, err
	}

	return token, nil
}



func CheckIfFileExists(path string, name string) bool {

	if _, err := os.Stat(path + name + ".yaml"); os.IsNotExist(err) {
		return false
	} else {
		return true
	}

}

func RemoveFile(path string, name string) bool {

	err := os.Remove(path + name + ".yaml")

	if err != nil {
		fmt.Printf("Did not delete file %s/%s", path, name)
		return false
	}

	return true
}
