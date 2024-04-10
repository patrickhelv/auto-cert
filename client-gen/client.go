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
)

func GenerateECDSAeKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateClientCertificate(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, clientKey *ecdsa.PrivateKey, validity time.Time, name string) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		return nil, err
	}

	clientCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{name},
		},
		NotBefore:   time.Now(),
		NotAfter:    validity, // 1 year validity time.Now().AddDate(1, 0, 0) time.Now().Add(365 * 24 * time.Hour)

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:        false,
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
