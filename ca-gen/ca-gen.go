package ca

import (
	"auto-cert/utility"
	"auto-cert/vault"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

func GenerateECDSAPrivateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateCACertificate(key *ecdsa.PrivateKey, ipAddresses []net.IP) (*x509.Certificate, []byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		return nil, nil, err
	}

	// Create SubjectAltName extension
    var sanExtension pkix.Extension
    if len(ipAddresses) > 0 {
        sanExtension, err = createSanExtension(ipAddresses)
        if err != nil {
            return nil, nil, err
        }
    }

	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ROS Shim CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years 
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if len(ipAddresses) > 0 {
        ca.ExtraExtensions = []pkix.Extension{sanExtension}
    }

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	return ca, caBytes, nil
}

func createSanExtension(ipAddresses []net.IP) (pkix.Extension, error) {
    var san pkix.Extension
    var err error

    rawValues := []asn1.RawValue{}

    for _, ip := range ipAddresses {
        rawValues = append(rawValues, asn1.RawValue{
            Class:      asn1.ClassContextSpecific,
            Tag:        7, // IP Address
            IsCompound: false,
            Bytes:      ip,
        })
    }

    san.Value, err = asn1.Marshal(rawValues)
    if err != nil {
        return san, err
    }

    san.Id = asn1.ObjectIdentifier{2, 5, 29, 17} // OID for Subject Alternative Name

    return san, nil
}

func CheckCertExpiry(pemData string, threshold time.Duration) (bool, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	expiry := cert.NotAfter
	if time.Until(expiry) < threshold {
		return true, nil // Certificate is expiring within the threshold
	}

	return false, nil // Certificate is not expiring within the threshold
}

func GetCert(pemData string) (*x509.Certificate, error){
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func PemToECDSA(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return key, nil
}

func PemToECDSAPub(pemData string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	ecdsaPub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not of type ECDSA")
	}

	return ecdsaPub, nil
}

func DecryptAndDecodeCa(path string, msg string, ENV bool) (string, string, error){
	certCAData, err := utility.DecodeYamlCertCa(path+"ca_cert.yaml")

	if err != nil {
		return "", "", fmt.Errorf("there was something decoding the ca cert %v", err)
	}

	caKeyData, err := utility.DecodeYamlCaKey(path+"ca_key.yaml")

	if err != nil {
		return "", "", fmt.Errorf("there was something wrong decoding the ca key, %v", err)
	}

	caCert, err := vault.DecryptAnsibleVaultFile(certCAData, msg, ENV)
	
	if err != nil {
		return "", "", fmt.Errorf("there was something wrong decrypting the ca certification %v", err)
	}

	caKey, err := vault.DecryptAnsibleVaultFile(caKeyData, msg, ENV)
	if err != nil {
		return "", "", fmt.Errorf("there was something wrong decrypting the ca key %v", err)
	}

	return caCert, caKey, nil
}