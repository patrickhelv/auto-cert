package main

import (
	"crypto/ecdsa"
	"auto-cert/ca-gen"
	"auto-cert/client-gen"
	"auto-cert/utility"
	"auto-cert/vault"
	"crypto/x509"
	"crypto/elliptic"
	"fmt"
	"time"
)

func generateCertificateClient(caCert *x509.Certificate, cakey *ecdsa.PrivateKey) (bool, *ecdsa.PrivateKey, []byte){

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

func generateCertificatesFirstTime(msg string, path string) bool {

	cakey, err := ca.GenerateECDSAPrivateKey(elliptic.P384())

	if err != nil {
		fmt.Println("There was an error generating the ca private key")
		return false
	}

	caCert, caCertificateBytes, err := ca.GenerateCACertificate(cakey)

	if err != nil {
		fmt.Println("There was an error generating the ca certificate")
		return false
	}

	status, clientkey, clientCertBytes := generateCertificateClient(caCert, cakey)
	
	if !status{
		return false
	}

	caCertPem := utility.EncodeToPEM(caCertificateBytes, true)
	caKeyPem := utility.EncodeToPEM(cakey.D.Bytes(), false)
	clientCertPem := utility.EncodeToPEM(clientCertBytes, true)
	clientKey := utility.EncodeToPEM(clientkey.D.Bytes(), false)

	err = vault.EncryptWithAnsibleVault(msg, caCertPem, "ca-cert", path)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, caKeyPem, "ca-key", path)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

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

func checkIsTheCAGenerated() {
	fmt.Println("hello")
	// TODO check if ca and other things exist
	// remove existing keys
	
}

func checkExpiryLoop(msg string, path string) {

	status := true

	for status {
		time.Sleep(36 * time.Hour)

		caCertYML, err := vault.DecryptAnsibleVaultFile(path+"/ca-cert.yaml", msg)
		if err != nil{
			status = false
			fmt.Println("There was something wrong decrypting the ca cert")
		}

		caKeyYML, err := vault.DecryptAnsibleVaultFile(path+"/ca-key.yaml", msg)
		if err != nil{
			status = false
			fmt.Println("There was something wrong decrypting the ca key")
		}

		clientCertYML, err := vault.DecryptAnsibleVaultFile(path+"/client-cert.yaml", msg)
		if err != nil{
			status = false
			fmt.Println("There was something wrong decrypting the client cert")
		}

		certCA, err := utility.DecodeYamlCert(caCertYML)


		expired, err := ca.CheckCertExpiry(certCA.Cert, 36*time.Hour)
		
		if err != nil{
			status = false
			fmt.Println("There was something checking the ca cert expiry")
		}

		if expired{
			// TODO expire CA, create a new CA invalidate the rest
		}

		if err != nil{
			status = false
			fmt.Println("There was something wrong decoding the yaml files")
		}

		certClient, err := utility.DecodeYamlCert(clientCertYML)

		ca.CheckCertExpiry(certClient.Cert, 36*time.Hour)

		if expired{
			// invalidate all the client keys and certs 

			caKey, err := utility.DecodeYamlKey(caKeyYML)
			if err != nil{
				status = false
				fmt.Println("There was something wrong decoding the ca key")
			}
			cacert, err := ca.GetCert(certCA.Cert)
			if err != nil{
				status = false
				fmt.Println("There was something wrong decoding the ca key")
			}
			cakey, err := ca.PemToECDSA(caKey.Private_key)
			if err != nil{
				status = false
				fmt.Println("There was something wrong decoding the ca key")
			}

			generateCertificateClient(cacert, cakey)
		}

		if err != nil{
			status = false
			fmt.Println("There was something wrong decoding the yaml files")
		}

	

	}
}

func main() {

	config, err := utility.FetchConfigFile("./config/configfile.txt")

	path := config[0]
	msg := config[1]

	if err != nil {
		fmt.Println("Error reading the config file")
		return
	}

	status := generateCertificatesFirstTime(msg, path)

	if !status {
		fmt.Println("Error creating certificates for the first time please verify check if something is wrong")
		return
	}

}
