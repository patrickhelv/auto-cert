package main

import (
	"auto-cert/ca-gen"
	"auto-cert/client-gen"
	"auto-cert/token-gen"
	"auto-cert/utility"
	"auto-cert/vault"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

var ENV bool

func generateCertificateClient(caCert *x509.Certificate, cakey *ecdsa.PrivateKey) (bool, *ecdsa.PrivateKey, []byte) {

	clientkey, err := client.GenerateECDSAeKey(elliptic.P256())

	if err != nil {
		fmt.Println("There was an error generating the client private key")
		return false, nil, nil
	}

	clientCertBytes, err := client.GenerateClientCertificate(caCert, cakey, clientkey)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false, nil, nil
	}

	return true, clientkey, clientCertBytes
}

func generateCa() (bool, *x509.Certificate, *ecdsa.PrivateKey, []byte) {

	cakey, err := ca.GenerateECDSAPrivateKey(elliptic.P256())

	if err != nil {
		fmt.Println("There was an error generating the ca private key")
		return false, nil, nil, nil
	}

	caCert, caCertificateBytes, err := ca.GenerateCACertificate(cakey)

	if err != nil {
		fmt.Println("There was an error generating the ca certificate")
		return false, nil, nil, nil
	}

	return true, caCert, cakey, caCertificateBytes
}

func generateCertificatesCaClient(msg string, path string) bool {

	status, caCert, cakey, caCertificateBytes := generateCa()

	if !status {
		return false
	}

	status, clientkey, clientCertBytes := generateCertificateClient(caCert, cakey)

	if !status {
		return false
	}

	caCertPem := utility.EncodeToPEMCert(caCertificateBytes)
	caKeyPem := utility.EncodeToPEMPK(cakey)
	clientCertPem := utility.EncodeToPEMCert(clientCertBytes)
	clientKey := utility.EncodeToPEMPK(clientkey)

	fmt.Println("Generating Certificates..")

	err := vault.EncryptWithAnsibleVault(msg, caCertPem, "ca_cert", path, ENV)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated CA cert")

	err = vault.EncryptWithAnsibleVault(msg, caKeyPem, "ca_key", path, ENV)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated CA key")

	err = vault.EncryptWithAnsibleVault(msg, clientCertPem, "client_cert", path, ENV)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated client cert")

	err = vault.EncryptWithAnsibleVault(msg, clientKey, "client_key", path, ENV)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated client key")
	return true
}

func generateNewClients(caKey string, certCA string, msg string, path string) bool {

	cacert, err := ca.GetCert(certCA)
	if err != nil {
		fmt.Println("There was something wrong decoding the ca certification")
		return false
	}

	cakey, err := ca.PemToECDSA(caKey)
	if err != nil {
		fmt.Println("There was something wrong translating to pem for the ca key")
		return false

	}

	state, clientkey, clientCertBytes := generateCertificateClient(cacert, cakey)

	if !state {
		fmt.Printf("There was something wrong generating the new client cert and key")
		return false
	}

	clientCertPem := utility.EncodeToPEMCert(clientCertBytes)

	clientKey := utility.EncodeToPEMPK(clientkey)

	err = vault.EncryptWithAnsibleVault(msg, clientCertPem, "client_cert", path, ENV)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, clientKey, "client_key", path, ENV)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	return true
}

func generateToken(msg string, path string) bool {

	tokenKey, err := client.GenerateECDSAeKey(elliptic.P256())

	if err != nil {
		fmt.Println("There was an error generating the token private key")
		return false
	}

	tokenStr := tokengen.GenerateJWT(tokenKey)

	fmt.Println("Generating a token")

	if tokenStr == "" {
		fmt.Println("There was an error generating the JWT token")
		return false
	}

	tokenKeyStr := utility.EncodeToPEMPubK(&tokenKey.PublicKey)

	err = vault.EncryptWithAnsibleVault(msg, tokenKeyStr, "token_key", path, ENV)

	if err != nil {
		fmt.Println("There was an error encrypting the token key")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, tokenStr, "token", path, ENV)

	if err != nil {
		fmt.Println("There was an error encrypting the token")
		return false
	}

	return true

}

func checkExpiryLoop(msg string, path string) {

	status := true

	for status {
		fmt.Println("Checking expiry...")

		time.Sleep(36 * time.Hour)

		tokenKeyPEM, err := utility.DecodeYamlTokenKey(path+"token_key.yaml")
		if err != nil {
			status = false
			fmt.Println("There was something wrong decoding the token key")
		}

		tokenKeyData, err := vault.DecryptAnsibleVaultFile(tokenKeyPEM.TokenKey, msg, ENV)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the token key")
		}

		tokenKey, err := ca.PemToECDSAPub(tokenKeyData)
		if err != nil {
			status = false
			fmt.Println("There was something wrong translating to pem for the ca key")
		}

		tokenData, err := utility.DecodeToken(path+"token.yaml")
		if err != nil {
			status = false
			fmt.Println("There was something wrong decoding the token")
		}

		token, err := vault.DecryptAnsibleVaultFile(tokenData.Token, msg, ENV)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the token")
		}

		expired, err := tokengen.CheckTokenExpiry(token, tokenKey)

		if err != nil {
			fmt.Println("There was something wrong checking the token expiry")
		}

		if expired {

			remstate1 := utility.RemoveFile(path, "token_key")
			remstate2 := utility.RemoveFile(path, "token")

			if !remstate1 && !remstate2 {
				status = false
				break
			}

			status = generateToken(msg, path)
		}

		certCAData, err := utility.DecodeYamlCertCa(path+"ca_cert.yaml")

		if err != nil {
			status = false
			fmt.Println("There was something decoding the ca cert")
		}

		caKeyData, err := utility.DecodeYamlCaKey(path+"ca_key.yaml")

		if err != nil {
			status = false
			fmt.Println("There was something wrong decoding the ca key")
		}

		clientCertData, err := utility.DecodeYamlClientCert(path+"client_cert.yaml")

		if err != nil {
			status = false
			fmt.Println("There was something wrong decoding the client cert")
		}


		caCert, err := vault.DecryptAnsibleVaultFile(certCAData.Carcert, msg, ENV)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the ca certification")
		}

		caKey, err := vault.DecryptAnsibleVaultFile(caKeyData.Cakey, msg, ENV)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the ca key")
		}

		clientCert, err := vault.DecryptAnsibleVaultFile(clientCertData.ClientCert, msg, ENV)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the client cert")
		}

		expired, err = ca.CheckCertExpiry(clientCert, 36*time.Hour)

		if err != nil {
			status = false
			fmt.Println("There was something wrong with the checking")
		}

		if expired {

			remstate1 := utility.RemoveFile(path, "client_cert")
			remstate2 := utility.RemoveFile(path, "client_key")

			if !remstate1 && !remstate2 {
				status = false
				break
			}

			status = generateNewClients(caKey, caCert, msg, path)
		}

		expired, err = ca.CheckCertExpiry(caCert, 36*time.Hour)

		if err != nil {
			status = false
			fmt.Println("There was something checking the ca cert expiry")
		}

		if expired {

			remstate1 := utility.RemoveFile(path, "ca_cert")
			remstate2 := utility.RemoveFile(path, "ca_key")
			remstate3 := utility.RemoveFile(path, "client_cert")
			remstate4 := utility.RemoveFile(path, "client_key")

			if !remstate1 && !remstate2 && !remstate3 && !remstate4 {
				status = false
				break
			}

			status = generateCertificatesCaClient(msg, path)
		}

	}
}

func main() {

	var path string
	var msg string
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


	if !utility.CheckIfFileExists(path, "ca_cert") && !utility.CheckIfFileExists(path, "ca_key") && !utility.CheckIfFileExists(path, "client_cert") {
		status := generateCertificatesCaClient(msg, path)

		fmt.Println("Generating CA and certificates for the first time")

		if !status {
			fmt.Println("Error creating certificates for the first time please verify check if something is wrong")
			return
		}
	}

	if !utility.CheckIfFileExists(path, "token_key") && !utility.CheckIfFileExists(path, "token") {

		status := generateToken(msg, path)

		fmt.Println("Generating token key and token for the first time")

		if !status {
			fmt.Println("Error creating certificates for the first time please verify check if something is wrong")
			return
		}
	}

	checkExpiryLoop(msg, path)

}
