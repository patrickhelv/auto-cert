package main

import (
	"auto-cert/ca-gen"
	"auto-cert/cert-gen"
	"auto-cert/client-gen"
	"auto-cert/token-gen"
	"auto-cert/utility"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

var ENV bool


type CaCertificate struct{
	Type string
	CertFileName string
	KeyFileName string
}


func checkAndUpdateToken(msg string, path string, cfg *utility.Config) error {
    
	fmt.Println("Checking token...")

	for _,entry := range cfg.Tokens{

		tokenKey, token, err := tokengen.DecodeAndDecryptToken(msg, path, ENV, entry.TokenFileName, entry.KeyFileName)
		if err != nil {
			return err
		}

		expired, err := tokengen.CheckTokenExpiry(token, tokenKey)
		if err != nil {
			return fmt.Errorf("checking token expiry: %v", err)
		}

		if expired {
			err := tokengen.RegenerateToken(msg, path, ENV, entry.TokenFileName, entry.KeyFileName)
			if err != nil {
				return fmt.Errorf("error regenerating a token: %v", err)
			}
		}
	}

	return nil
}


func checkAndUpdateCertificates(msg, path string, cfg *utility.Config) error{
	
	caCert, caKey, err := ca.DecryptAndDecodeCa(path, msg, ENV)

	fmt.Println("Checking certificates...")

	if err != nil{
		return fmt.Errorf("there is an error in decrypting the caCert and the caKey, %v", err)
	}

	for host,entry := range cfg.Hosts{
		fmt.Printf("Processing certificates for host: %s\n", host)

		clientCert, err := client.DecodeAndDecryptCertClient(path, msg, entry.ClientCert.CertFileName, ENV)

		if err != nil{
			return fmt.Errorf("there was an error decoding and decrypting the Cert Client %v", err)
		}

		expired, err := ca.CheckCertExpiry(clientCert, 36*time.Hour)

		if err != nil {
			return fmt.Errorf("there was something wrong with the client cert check for expiry, %v", err)
		}

		if expired{

			remstate1 := utility.RemoveFile(path, entry.ClientCert.CertFileName)
			remstate2 := utility.RemoveFile(path, entry.ClientCert.KeyFileName)

			if !remstate1 && !remstate2 {
				return fmt.Errorf("could not remove cert files %s and key file %s", entry.ClientCert.CertFileName, entry.ClientCert.KeyFileName)
			}

			status := certgen.GenerateNewClient(caKey, caCert, msg, path, ENV, entry.ClientCert.CertFileName, entry.ClientCert.KeyFileName, entry.ClientCert.CommonNameStr, entry.ClientCert.SANStr, entry.ClientCert.Type)

			if !status{
				return fmt.Errorf("error generating new client key and cert")
			}
		}

		serverCert, err := client.DecodeAndDecryptCertServer(path, msg, entry.ServerCert.CertFileName, ENV)

		if err != nil{
			return fmt.Errorf("there was an error decoding and decrypting the server cert, %v", err)
		}

		expired, err = ca.CheckCertExpiry(serverCert, 36*time.Hour)

		if err != nil {
			return fmt.Errorf("there was something wrong with the server cert check for expiry")
		}

		if expired{

			remstate1 := utility.RemoveFile(path, entry.ServerCert.CertFileName)
			remstate2 := utility.RemoveFile(path, entry.ServerCert.KeyFileName)

			if !remstate1 && !remstate2 {
				return fmt.Errorf("could not remove server cert files %s and key file %s", entry.ServerCert.CertFileName, entry.ServerCert.KeyFileName)
			}

			status := certgen.GenerateNewServer(caKey, caCert, msg, path, ENV, entry.ServerCert.CertFileName, entry.ServerCert.KeyFileName, entry.ServerCert.CommonNameStr, entry.ServerCert.SANStr, entry.ServerCert.Type)

			if !status{
				return fmt.Errorf("error generating new server key and cert")
			}
		}
	}

	return nil
}

func checkAndUpdateCA(msg, path string, cfg *utility.Config) (error){
	caCert, _, err := ca.DecryptAndDecodeCa(path, msg, ENV)

	fmt.Println("Checking CA...")
	if err != nil{
		return fmt.Errorf("there is an error decrypting the CA, %v", err)
	}
	
	status, err := ca.CheckCertExpiry(caCert, 24 * time.Hour)

	if err != nil{
		return fmt.Errorf("there is an error checking the expiration of the CA, %v", err)
	}

	if status{

		status, caCertNew, caKeyNew, caCertificateBytes := certgen.GenerateCa()

		if !status{
			return fmt.Errorf("there was an error generacting a new CA after the expiry date")
		}

		if utility.CheckIfFileExists(path, "ca_cert"){
			utility.RemoveFile(path, "ca_cert")
		}

		if utility.CheckIfFileExists(path, "ca_key"){
			utility.RemoveFile(path, "ca_key")
		}

		status = certgen.EncryptCaCert(caCertificateBytes, caKeyNew, msg, path, ENV)

		if !status{
			return fmt.Errorf("there was an error encrypting the CA certification")
		}
		status = generateCertificatesFirstTime(path, msg, cfg, caCertNew, caKeyNew, caCertificateBytes)

		if !status{
			return fmt.Errorf("there was an error regenerating each certificate with the new CA")
		}
	}

	return nil
}



func checkAndUpdateAll(msg string, path string, cfg *utility.Config) bool {

	if err := checkAndUpdateCA(msg, path, cfg); err != nil{
		fmt.Printf("there was an error checking CA %v\n", err)
		return false
	}

    if err := checkAndUpdateToken(msg, path, cfg); err != nil {
		fmt.Printf("there was an error checking tokens %v\n", err)
        return false
    }

    if err := checkAndUpdateCertificates(msg, path, cfg); err != nil {
		fmt.Printf("there was an error checking certificates %v\n", err)
        return false
    }

    return true
}


func checkExpiryLoop(msg string, path string, cfg *utility.Config) {

	status := true

	for status {
		fmt.Println("Checking expiry...")

		time.Sleep(36 * time.Hour)

		status = checkAndUpdateAll(msg, path, cfg)
	}
}

func generateCertificatesFirstTime(path string, msg string, cfg *utility.Config, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caCertificateBytes []byte) (bool){
	for _,entry := range cfg.Hosts{

		if utility.CheckIfFileExists(path, entry.ClientCert.CertFileName) {
			utility.RemoveFile(path, entry.ClientCert.CertFileName)
		}

		status := certgen.GenerateClientCert(caCert, caCertificateBytes, caKey, msg, path, ENV, entry.ClientCert.CertFileName, entry.ClientCert.KeyFileName, entry.ClientCert.CommonNameStr, entry.ClientCert.SANStr, entry.ClientCert.Type)
		if !status{
			fmt.Println("There was an error generating the client cert for the first time")
			return false
		}
	
		if utility.CheckIfFileExists(path, entry.ServerCert.CertFileName) {
			utility.RemoveFile(path, entry.ServerCert.KeyFileName)
		}

		status = certgen.GenerateServerCert(caCert, caKey, caCertificateBytes, msg, path, ENV, entry.ServerCert.CertFileName, entry.ServerCert.KeyFileName, entry.ServerCert.CommonNameStr, entry.ServerCert.SANStr, entry.ServerCert.Type)
		
		if !status{
			fmt.Println("There was an error generating the server cert for the first time")
			return false
		}
	}

	for _,entry := range cfg.Tokens{
		
		if utility.CheckIfFileExists(path, entry.TokenFileName) {
			utility.RemoveFile(path, entry.TokenFileName)
		}
		
		status := tokengen.GenerateToken(msg, path, ENV, entry.TokenFileName, entry.KeyFileName)

		if !status{
			fmt.Println("There was an error generating the tokens for the first time")
			return false
		}
	}

	return true
}



func main() {

	var path string
	var msg string

	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey
	var caCertificateBytes []byte

	var status bool


	var CONFIG_VAULT_PATH = "VAULT_PATH"
	var CONFIG_VAULT_PASS = "ANSIBLE_VAULT_PASSWORD"

	path = os.Getenv(CONFIG_VAULT_PATH)
	msg = os.Getenv(CONFIG_VAULT_PASS)

	if path == "" && msg == ""{
		config, err := utility.FetchConfigFile("/root/config/configfile.txt")

		if err != nil {
			fmt.Println("Error reading the config file")
			return
		}

		path = config[0]
		msg = config[1]
		ENV = false

	}else{

		ENV = true
	}

	cfg, err := utility.ReadCertConfig("/root/config/configcerts.ini")

	if err != nil{
		fmt.Printf("there was an error reading the cert config file %v", err)
	}

	if !utility.CheckIfFileExists(path, "ca_cert") || !utility.CheckIfFileExists(path, "ca_key"){
		
		if utility.CheckIfFileExists(path, "ca_cert"){
			utility.RemoveFile(path, "ca_cert")
		}

		if utility.CheckIfFileExists(path, "ca_key"){
			utility.RemoveFile(path, "ca_key")
		}

		fmt.Println("Generating CA for the first time")
		status, caCert, caKey, caCertificateBytes = certgen.GenerateCa()

		if !status {
			fmt.Println("There was an error generating the first CA")
			return 
		}

		status = certgen.EncryptCaCert(caCertificateBytes, caKey, msg, path, ENV)

		if !status {
			fmt.Println("There was an error encrypting and storing the first CA")
			return 
		}

	}

	if caCert == nil && caKey == nil{
		
		fmt.Println("Generating client and server certificates specified in the configcerts.ini")
		status := checkAndUpdateAll(msg, path, cfg)
		if !status{
			return
		}

	}else{

		fmt.Println("Generating client and server certificates specified in the configcerts.ini for the first time")
		status := generateCertificatesFirstTime(path, msg, cfg, caCert, caKey, caCertificateBytes)
		if !status{
			return
		}
	}

	checkExpiryLoop(msg, path, cfg)

}
