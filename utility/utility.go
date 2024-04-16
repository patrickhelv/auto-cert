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
	"auto-cert/certificate"
)

type CaCertification struct {
	Carcert string `yaml:"ca_cert"`
}

type ClientCertification struct {
	ClientCert string `yaml:"client_cert"`
}

type ServerCertification struct {
	ServerCert string `yaml:"server_cert"`
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

// Config structure now holds slices of specific certificate types.
type Config struct {
    ClientCerts []cert.ClientCertificate
    ServerCerts []cert.ServerCertificate
    Tokens      []cert.Token
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

func ReadCertConfig(filename string) (*Config, error){
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    cfg := &Config{}
    var currentKey string

    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
            currentKey = line
        } else {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) == 2 {
                key := strings.TrimSpace(parts[0])
                value := strings.TrimSpace(parts[1])
                if currentKey == "[clientcert]" {
                    if key == "NAME" {
                        cfg.ClientCerts = append(cfg.ClientCerts, cert.ClientCertificate{
                            Type:        "Client",
                            CertFileName: value,
                            KeyFileName:  "", // Placeholder, to be filled in next valid KEYNAME
                        })
                    } else if key == "KEYNAME" && len(cfg.ClientCerts) > 0 {
                        cfg.ClientCerts[len(cfg.ClientCerts)-1].KeyFileName = value
                    }
                } else if currentKey == "[servercert]" {
                    if key == "NAME" {
                        cfg.ServerCerts = append(cfg.ServerCerts, cert.ServerCertificate{
                            Type:        "Server",
                            CertFileName: value,
                            KeyFileName:  "", // Placeholder, to be filled in next valid KEYNAME
                        })
                    } else if key == "KEYNAME" && len(cfg.ServerCerts) > 0 {
                        cfg.ServerCerts[len(cfg.ServerCerts)-1].KeyFileName = value
                    }
                } else if currentKey == "[token]" {
                    if key == "NAME" {
                        cfg.Tokens = append(cfg.Tokens, cert.Token{
                            Type:         "Token",
                            TokenFileName: value,
                            KeyFileName:  "", // Placeholder, to be filled in next valid KEYNAME
                        })
                    } else if key == "KEYNAME" && len(cfg.Tokens) > 0 {
                        cfg.Tokens[len(cfg.Tokens)-1].KeyFileName = value
                    }
                }
            }
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return cfg, nil
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

func DecodeYamlCertCa(filePath string) (string, error) {

	var cert CaCertification

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return "", err
	}

	err = yaml.Unmarshal([]byte(data), &cert)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return cert.Carcert, nil
}

func DecodeYamlClientCert(filePath string) (string, error) {

	var cert ClientCertification

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return "", err
	}

	err = yaml.Unmarshal([]byte(data), &cert)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return cert.ClientCert, nil
}

func DecodeYamlServerCert(filePath string) (string, error) {

	var cert ServerCertification

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return "", err
	}

	err = yaml.Unmarshal([]byte(data), &cert)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return cert.ServerCert, nil
}

func DecodeYamlCaKey(filePath string) (string, error) {

	var key CaPKey

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return "", err
	}

	err = yaml.Unmarshal([]byte(data), &key)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return key.Cakey, nil
}

func DecodeYamlClientKey(filePath string) (string, error) {

	var key ClientPKey

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return "", err
	}

	err = yaml.Unmarshal([]byte(data), &key)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return key.ClientKey, nil
}

func DecodeYamlTokenKey(filePath string) (string, error) {

	var key TokenPKey

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return "", err
	}

	err = yaml.Unmarshal([]byte(data), &key)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return key.TokenKey, nil
}

func DecodeToken(filePath string) (string, error) {

	var token Token

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("error reading file: %v", err)
		return "", err
	}

	err = yaml.Unmarshal([]byte(data), &token)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return token.Token, nil
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
		fmt.Printf("Did not delete file %s%s\n", path, name)
		return false
	}

	return true
}
