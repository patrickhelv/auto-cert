package tokengen

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

func GenerateJWT(tokenKey *ecdsa.PrivateKey) string {
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
