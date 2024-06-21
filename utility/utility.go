package utility

import (
	"auto-cert/certificate"
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v2"
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
    Hosts  map[string]cert.HostConfig
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

func ReadCertConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	cfg := &Config{
		Hosts: make(map[string]cert.HostConfig),
	}
	var currentSection string
	var currentHost string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line
			if currentSection != "[token]" {
				currentHost = strings.Trim(currentSection, "[]")
			}
		} else {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if strings.HasPrefix(currentSection, "[host") {
					if _, exists := cfg.Hosts[currentHost]; !exists {
						cfg.Hosts[currentHost] = cert.HostConfig{}
					}
					hostConfig := cfg.Hosts[currentHost]
					switch key {
					case "server_cert_name":
						hostConfig.ServerCert.CertFileName = value
					case "server_key_name":
						hostConfig.ServerCert.KeyFileName = value
					case "server_cn":
						hostConfig.ServerCert.CommonNameStr = value
					case "server_san":
						hostConfig.ServerCert.SANStr = value
					case "client_cert_name":
						hostConfig.ClientCert.CertFileName = value
					case "client_key_name":
						hostConfig.ClientCert.KeyFileName = value
					case "client_cn":
						hostConfig.ClientCert.CommonNameStr = value
					case "client_san":
						hostConfig.ClientCert.SANStr = value
					}
					cfg.Hosts[currentHost] = hostConfig
				} else if currentSection == "[token]" {
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
	var CONFIG_PLAYBOOK = "PLAYBOOK_OPTION"

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

	if val, exists := configFileMap[CONFIG_PLAYBOOK]; exists {
		result = append(result, val)
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

func ExecutePlayBook(category string, vaultPasswordFile string) (error){

	var cmds []*exec.Cmd
	
	if category == "token-refresh"{
		cmds =  append(cmds, exec.Command("ansible-playbook", "./playbooks/token_update_task.yaml", "--vault-password-file", vaultPasswordFile))
	}else if category == "cert-refresh"{
		// cmds =  append(cmds, exec.Command("ansible-playbook", "./playbooks/shim_1_task.yaml", "--vault-password-file", vaultPasswordFile))
		cmds = append(cmds, exec.Command("ansible-playbook", "./playbooks/shim_2_task.yaml", "--vault-password-file", vaultPasswordFile))
	}
	 
	for _, cmd := range cmds {
        err := cmd.Run()
        if err != nil {
            return fmt.Errorf("failed to execute playbook %s: %v", category, err)
        }
    }
 
	return nil
}
