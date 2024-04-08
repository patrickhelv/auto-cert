package main

import (
	"auto-cert/ca-gen"
	"auto-cert/client-gen"
	"auto-cert/utility"
	"auto-cert/vault"
	"auto-cert/token-gen"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"time"
)

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

	cakey, err := ca.GenerateECDSAPrivateKey(elliptic.P384())

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

	caCertPem := utility.EncodeToPEM(caCertificateBytes, true)
	caKeyPem := utility.EncodeToPEM(cakey.D.Bytes(), false)
	clientCertPem := utility.EncodeToPEM(clientCertBytes, true)
	clientKey := utility.EncodeToPEM(clientkey.D.Bytes(), false)

	fmt.Println("Generating Certificates..")

	err := vault.EncryptWithAnsibleVault(msg, caCertPem, "ca-cert", path)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated CA cert")

	err = vault.EncryptWithAnsibleVault(msg, caKeyPem, "ca-key", path)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated CA key")

	err = vault.EncryptWithAnsibleVault(msg, clientCertPem, "client-cert", path)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated client cert")

	err = vault.EncryptWithAnsibleVault(msg, clientKey, "client-key", path)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated client key")
	return true
}

func generateNewClients(caKeyYML string, certCA utility.CaCertification, msg string, path string) (bool){
	caKey, err := utility.DecodeYamlCaKey(caKeyYML)
	if err != nil {
		fmt.Println("There was something wrong decoding the ca key")
		return false
	}
	
	cacert, err := ca.GetCert(certCA.Carcert)
	if err != nil {
		fmt.Println("There was something wrong decoding the ca key")
		return false
	}

	cakey, err := ca.PemToECDSA(caKey.Cakey)
	if err != nil {
		fmt.Println("There was something wrong translating to pem for the ca key")
		return false
		
	}

	state, clientkey, clientCertBytes := generateCertificateClient(cacert, cakey)

	if !state {
		fmt.Printf("There was something wrong generating the new client cert and key")
		return false
	}

	clientCertPem := utility.EncodeToPEM(clientCertBytes, true)

	clientKey := utility.EncodeToPEM(clientkey.D.Bytes(), false)

	err = vault.EncryptWithAnsibleVault(msg, clientCertPem, "client-cert", path)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, clientKey, "client-key", path)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	return true
}

func generateToken(msg string, path string) (bool){

	tokenKey, err := client.GenerateECDSAeKey(elliptic.P256())

	if err != nil {
		fmt.Println("There was an error generating the token private key")
		return false
	}

	tokenStr := tokengen.GenerateJWT(tokenKey)

	if tokenStr == ""{
		fmt.Println("There was an error generating the JWT token")
		return false
	}

	tokenKeyStr := utility.EncodeToPEM(tokenKey.D.Bytes(), false)

	err = vault.EncryptWithAnsibleVault(msg, tokenKeyStr, "token-key", path)
	
	if err != nil {
		fmt.Println("There was an error encrypting the token key")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, tokenStr, "token", path)
	
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

		tokenKeyYML, err := vault.DecryptAnsibleVaultFile(path+"token-key.yaml", msg)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the token key")
		}

		tokenKeyPEM, err := utility.DecodeYamlTokenKey(tokenKeyYML)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decoding the token key")
		}

		tokenKey, err := ca.PemToECDSA(tokenKeyPEM.TokenKey)
		if err != nil {
			status = false
			fmt.Println("There was something wrong translating to pem for the ca key")
		}

		tokenYML, err := vault.DecryptAnsibleVaultFile(path+"token.yaml", msg)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the token")
		}

		token, err := utility.DecodeToken(tokenYML)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decoding the token")
		}
		
		expired, err := tokengen.CheckTokenExpiry(token.Auth.JwtToken, &tokenKey.PublicKey)

		if err != nil {
			status = false
			fmt.Println("There was something wrong checking the token expiry")
		}


		if expired{

			remstate1 := utility.RemoveFile(path, "token-key")
			remstate2 := utility.RemoveFile(path, "token")

			if remstate1 && remstate2{
				status = false
				break
			}

			status = generateToken(msg, path)
		}

		caCertYML, err := vault.DecryptAnsibleVaultFile(path+"ca-cert.yaml", msg)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the ca cert")
		}

		caKeyYML, err := vault.DecryptAnsibleVaultFile(path+"ca-key.yaml", msg)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the ca key")
		}

		clientCertYML, err := vault.DecryptAnsibleVaultFile(path+"client-cert.yaml", msg)
		if err != nil {
			status = false
			fmt.Println("There was something wrong decrypting the client cert")
		}

		certCA, err := utility.DecodeYamlCertCa(caCertYML)

		if err != nil {
			status = false
			fmt.Println("There was something decoding the ca cert")
		}

		certClient, err := utility.DecodeYamlClientCa(clientCertYML)
		
		if err != nil {
			status = false
			fmt.Println("There was something wrong decoding the yaml files")
		}

		expired, err = ca.CheckCertExpiry(certClient.ClientCert, 36*time.Hour)

		if err != nil {
			status = false
			fmt.Println("There was something wrong with the checking")
		}

		if expired {

			remstate1 := utility.RemoveFile(path, "client-cert")
			remstate2 := utility.RemoveFile(path, "client-key")

			if remstate1 && remstate2{
				status = false
				break
			}
		
			status = generateNewClients(caKeyYML, certCA, msg, path)
		}

		expired, err = ca.CheckCertExpiry(certCA.Carcert, 36*time.Hour)

		if err != nil {
			status = false
			fmt.Println("There was something checking the ca cert expiry")
		}

		if expired {

			remstate1 := utility.RemoveFile(path, "ca-cert")
			remstate2 := utility.RemoveFile(path, "ca-key")
			remstate3 := utility.RemoveFile(path, "client-cert")
			remstate4 := utility.RemoveFile(path, "client-key")


			if remstate1 && remstate2 && remstate3 && remstate4{
				status = false
				break
			}

			status = generateCertificatesCaClient(msg, path)
		}

	}
}

func main() {

	config, err := utility.FetchConfigFile("/root/config/configfile.txt")

	path := config[0]
	msg := config[1]

	if err != nil {
		fmt.Println("Error reading the config file")
		return
	}

	if !utility.CheckIfFileExists(path, "ca-cert") && !utility.CheckIfFileExists(path, "ca-key") && !utility.CheckIfFileExists(path, "client-cert"){
		status := generateCertificatesCaClient(msg, path)
		
		fmt.Println("Generating CA and certificates for the first time")

		if !status {
			fmt.Println("Error creating certificates for the first time please verify check if something is wrong")
			return
		}
	}

	if !utility.CheckIfFileExists(path, "token-key") && !utility.CheckIfFileExists(path, "token"){

		status := generateToken(msg, path)

		fmt.Println("Generating token key and token for the first time")

		if !status {
			fmt.Println("Error creating certificates for the first time please verify check if something is wrong")
			return
		}
	}
	

	checkExpiryLoop(msg, path)

}
