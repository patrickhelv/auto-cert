package certgen

import (
	"auto-cert/ca-gen"
	"auto-cert/client-gen"
	"auto-cert/utility"
	"auto-cert/vault"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"time"
)

func GenerateCa() (bool, *x509.Certificate, *ecdsa.PrivateKey, []byte) {

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

func generateCertificateClient(caCert *x509.Certificate, cakey *ecdsa.PrivateKey, commonName string, san string) (bool, *ecdsa.PrivateKey, []byte) {

	clientkey, err := client.GenerateECDSAeKey(elliptic.P256())

	if err != nil {
		fmt.Println("There was an error generating the client private key")
		return false, nil, nil
	}
	
	clientCertBytes, err := client.GenerateClientCertificate(caCert, cakey, clientkey, time.Now().AddDate(1, 0, 0), "ros2-shim", commonName, san)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false, nil, nil
	}

	return true, clientkey, clientCertBytes
}


func generateSCertificateServer(caCert *x509.Certificate, cakey *ecdsa.PrivateKey, commonName string, san string) (bool, *ecdsa.PrivateKey, []byte){

	serverKey, err := client.GenerateECDSAeKey(elliptic.P256())

	if err != nil {
		fmt.Println("There was an error generating the server private key")
		return false, nil, nil
	}

	serverCertBytes, err := client.GenerateClientCertificate(caCert, cakey, serverKey, time.Now().AddDate(1, 0, 0), "controller", commonName, san)

	if err != nil {
		fmt.Println("There was an error generating the server certificate")
		return false, nil, nil
	}

	return true, serverKey, serverCertBytes
}

func GenerateNewClient(caKey string, certCA string, msg string, path string, ENV bool, variableName string, variableKeyName string, commonName string, san string) bool {

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

	state, clientkey, clientCertBytes := generateCertificateClient(cacert, cakey, commonName, san)

	if !state {
		fmt.Printf("There was something wrong generating the new client cert and key")
		return false
	}

	clientCertPem := utility.EncodeToPEMCert(clientCertBytes)

	clientKey := utility.EncodeToPEMPK(clientkey)

	err = vault.EncryptWithAnsibleVault(msg, clientCertPem, "client_cert", path, ENV, variableName)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, clientKey, "client_key", path, ENV, variableKeyName)

	if err != nil {
		fmt.Println("There was an error generating the client key")
		return false
	}

	return true
}

func GenerateNewServer(caKey string, certCA string, msg string, path string, ENV bool, variableName string, variableNameKey string, commonName string, san string) bool {

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

	state, serverkey, serverCertBytes := generateCertificateClient(cacert, cakey, commonName, san)

	if !state {
		fmt.Printf("There was something wrong generating the new client cert and key")
		return false
	}

	serverCertPem := utility.EncodeToPEMCert(serverCertBytes)

	serverKey := utility.EncodeToPEMPK(serverkey)

	err = vault.EncryptWithAnsibleVault(msg, serverCertPem, "server_cert", path, ENV, variableName)

	if err != nil {
		fmt.Println("There was an error generating the server certificate")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, serverKey, "server_key", path, ENV, variableNameKey)

	if err != nil {
		fmt.Println("There was an error generating the server key")
		return false
	}

	return true
}

func EncryptCaCert(caCertificateBytes []byte, cakey *ecdsa.PrivateKey, msg string, path string, ENV bool) (bool){
	caCertPem := utility.EncodeToPEMCert(caCertificateBytes)
	caKeyPem := utility.EncodeToPEMPK(cakey)

	variableName := "ca_cert"
	variableNameKey := "ca_key"


	err := vault.EncryptWithAnsibleVault(msg, caCertPem, "ca_cert", path, ENV, variableName)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated CA cert")

	err = vault.EncryptWithAnsibleVault(msg, caKeyPem, "ca_key", path, ENV, variableNameKey)
	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated CA key")

	return true

}

func GenerateClientCert(caCert *x509.Certificate, caCertificateBytes []byte, cakey *ecdsa.PrivateKey, msg string, path string, ENV bool, variableName string, variableNameKey string, commonName string, san string) (bool){
	
	status, clientKey,clientCertBytes := generateCertificateClient(caCert, cakey, commonName, san)

	if !status{
		fmt.Println("There was an error generating the Client key and Client certificate")
		return false 
	}
	
	clientCertPem := utility.EncodeToPEMCert(clientCertBytes)
	clientKeyPem := utility.EncodeToPEMPK(clientKey)

	err := vault.EncryptWithAnsibleVault(msg, clientCertPem, "client_cert", path, ENV, variableName)

	if err != nil {
		fmt.Println("There was an error generating the client certificate")
		return false
	}

	fmt.Println("Generated client cert")

	err = vault.EncryptWithAnsibleVault(msg, clientKeyPem, "client_key", path, ENV, variableNameKey)

	if err != nil {
		fmt.Println("There was an error generating the client keey")
		return false
	}

	fmt.Println("Generated client key")
	
	return true
}


func GenerateServerCert(caCert *x509.Certificate, cakey *ecdsa.PrivateKey, caCertificateBytes []byte, msg string, path string, ENV bool, variableName string, variableKeyName string, commonName string, san string) bool {

	status, serverkey, serverCertBytes := generateSCertificateServer(caCert, cakey, commonName, san)

	if !status {

		return false
	}

	serverCertPem := utility.EncodeToPEMCert(serverCertBytes)
	serverKey := utility.EncodeToPEMPK(serverkey)

	err := vault.EncryptWithAnsibleVault(msg, serverCertPem, "server_cert", path, ENV, variableName)

	if err != nil {
		fmt.Println("There was an error generating the server certificate")
		return false
	}

	fmt.Println("Generated server cert")

	err = vault.EncryptWithAnsibleVault(msg, serverKey, "server_key", path, ENV, variableKeyName)

	if err != nil {
		fmt.Println("There was an error generating the server key")
		return false
	}

	fmt.Println("Generated server key")

	return true
}

