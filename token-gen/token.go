package tokengen

import (
	"auto-cert/ca-gen"
	"auto-cert/client-gen"
	"auto-cert/utility"
	"auto-cert/vault"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

func generateJWT(tokenKey *ecdsa.PrivateKey) string {
	// Create a new token object, specifying signing method and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user": "rosNode",
		"exp":  time.Now().Add(time.Hour * 80).Unix(),
	})

	// Sign the token with the private key
	tokenString, err := token.SignedString(tokenKey)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	return tokenString
}

func CheckTokenExpiry(tokenStr string, PubtokenKey *ecdsa.PublicKey) (bool, error) {

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return PubtokenKey, nil
	})

	if err != nil {
		fmt.Printf("There was an error parsing the token string, %v\n", err)
		return true, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("Token is valid.")
		exp := int64(claims["exp"].(float64))
		currentTime := time.Now().Unix()
		difference := exp - currentTime

		if difference < 86400 {
			fmt.Println("The token's expiration is less than 24 hours away.")
			return true, nil
		} else {
			return false, nil
		}

	} else {
		fmt.Println(err)
		return false, err
	}

}

func GenerateToken(msg string, path string, ENV bool, variableName string, variableKeyName string) bool {

	tokenKey, err := client.GenerateECDSAeKey(elliptic.P256())

	if err != nil {
		fmt.Println("There was an error generating the token private key")
		return false
	}

	tokenStr := generateJWT(tokenKey)

	fmt.Println("Generating a token")

	if tokenStr == "" {
		fmt.Println("There was an error generating the JWT token")
		return false
	}

	tokenKeyStr := utility.EncodeToPEMPubK(&tokenKey.PublicKey)

	err = vault.EncryptWithAnsibleVault(msg, tokenKeyStr, "token_key", path, ENV, variableKeyName)

	if err != nil {
		fmt.Println("There was an error encrypting the token key")
		return false
	}

	err = vault.EncryptWithAnsibleVault(msg, tokenStr, "token", path, ENV, variableName)

	if err != nil {
		fmt.Println("There was an error encrypting the token")
		return false
	}

	return true

}

func DecodeAndDecryptToken(msg, path string, ENV bool, variableName string, variableNameKey string) (*ecdsa.PublicKey, string, error) {
    tokenKeyYML, err := utility.DecodeYamlTokenKey(path + variableNameKey + ".yaml")
    if err != nil {
        return nil, "", fmt.Errorf("decoding token key: %v", err)
    }

    tokenKeyData, err := vault.DecryptAnsibleVaultFile(tokenKeyYML, msg, ENV)
    if err != nil {
        return nil, "", fmt.Errorf("decrypting token key: %v", err)
    }

	
	tokenKey, err := ca.PemToECDSAPub(tokenKeyData)
	if err != nil {
		return nil, "", fmt.Errorf("there was something wrong translating to pem for the ca key: %v", err)
	}

    tokenData, err := utility.DecodeToken(path + variableName +".yaml")
    if err != nil {
        return nil, "", fmt.Errorf("decoding token: %v", err)
    }

    token, err := vault.DecryptAnsibleVaultFile(tokenData, msg, ENV)
    if err != nil {
        return nil, "", fmt.Errorf("decrypting token: %v", err)
    }

    return tokenKey, token, nil
}

func removeTokenFiles(path, variableName, variableNameKey string) error {
    remstate1 := utility.RemoveFile(path, variableName)
    remstate2 := utility.RemoveFile(path, variableNameKey)
    if !remstate1 || !remstate2 {
        return fmt.Errorf("failed to remove token files")
    }
    return nil
}

func RegenerateToken(msg string, path string, ENV bool, variableName string, variableNameKey string) error {
    if err := removeTokenFiles(path, variableName, variableNameKey); err != nil {
        return err
    }

    if !GenerateToken(msg, path, ENV, variableName, variableNameKey) {
        return fmt.Errorf("failed to regenerate token")
    }

    return nil
}