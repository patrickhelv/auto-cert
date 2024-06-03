package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
	"encoding/pem"
	"os"
	"fmt"

	"auto-cert/utility"
	"auto-cert/vault"
)

func GenerateECDSAeKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err	
	}
	return key, nil
}

func GenerateClientCertificate(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, clientKey *ecdsa.PrivateKey, validity time.Time, name string, commonName string, san string) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		return nil, err
	}

	clientCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{name},
		},
		NotBefore:   time.Now(),
		NotAfter:    validity, // 1 year validity time.Now().AddDate(1, 0, 0) time.Now().Add(365 * 24 * time.Hour)
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:        false,
	}

	if san != "" {
		clientCert.DNSNames = []string{san}
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientCert, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return clientCertBytes, nil
}

func GenerateServerCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, clientKey *ecdsa.PrivateKey, validity time.Time, name string, commonName string, san string) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		return nil, err
	}

	clientCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{name},
		},
		NotBefore:   time.Now(),
		NotAfter:    validity, // 1 year validity time.Now().AddDate(1, 0, 0) time.Now().Add(365 * 24 * time.Hour)
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:        false,
	}

	if san != "" {
		clientCert.DNSNames = []string{san}
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientCert, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return clientCertBytes, nil
}

func WritePrivateKeyToFile(key *ecdsa.PrivateKey, filename string) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	return os.WriteFile(filename, keyPEM, 0600) // Ensure file is only readable by the user
}

func DecodeAndDecryptCertClient(path string, msg string, name string, ENV bool) (string, error){

	clientCertData, err := utility.DecodeYamlClientCert(path+name+".yaml")

	if err != nil {
		return "", fmt.Errorf("there was something wrong decoding the client cert, %v", err)
	}

	clientCert, err := vault.DecryptAnsibleVaultFile(clientCertData, msg, ENV)
	if err != nil {
		return "", fmt.Errorf("there was something wrong decrypting the client cert, %v", err)
	}

	return clientCert, nil
}

func DecodeAndDecryptCertServer(path string, msg string, name string, ENV bool) (string, error){

	serverCertData, err := utility.DecodeYamlServerCert(path+name+".yaml")

	if err != nil {
		return "", fmt.Errorf("there was something wrong decoding the server cert, %v", err)
	}

	serverCert, err := vault.DecryptAnsibleVaultFile(serverCertData, msg, ENV)
	if err != nil {
		return "", fmt.Errorf("there was something wrong decrypting the server cert %v", err)
	}

	return serverCert, nil
}



