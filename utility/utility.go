package utility

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
	"strings"
)

type Certificate struct {
	Cert string `yaml:"certificate"`
}

type Key struct {
	Private_key string `yaml:"private_key"`
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

// Function to encode certificate or key bytes to PEM format
func EncodeToPEM(certBytes []byte, isCert bool) string {
	pemType := "CERTIFICATE"
	if !isCert {
		pemType = "PRIVATE KEY" // Adjust this based on the actual type of key (RSA PRIVATE KEY, EC PRIVATE KEY, etc.)
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: certBytes,
	}

	var pemBuf bytes.Buffer
	err := pem.Encode(&pemBuf, pemBlock)
	if err != nil {
		fmt.Printf("Error encoding to PEM: %v\n", err)
		return ""
	}

	return pemBuf.String()
}

func DecodeYamlCert(decryptedContent string) (Certificate, error) {

	var cert Certificate

	err := yaml.Unmarshal([]byte(decryptedContent), &cert)
	if err != nil {
		fmt.Println(err)
		return cert, err
	}

	return cert, err
}

func DecodeYamlKey(decryptedContent string) (Key, error) {

	var key Key

	err := yaml.Unmarshal([]byte(decryptedContent), &key)
	if err != nil {
		fmt.Println(err)
		return key, err
	}

	return key, err
}
