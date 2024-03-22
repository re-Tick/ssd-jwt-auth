package ssdjwtauth

import (
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	KeyID string
	Key   crypto.PrivateKey
}

func NewSigner(keyID string, pemkey []byte) (*Signer, error) {
	rk, err := jwt.ParseRSAPrivateKeyFromPEM(pemkey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key PEM for keyid %s: %v", keyID, err)
	}
	s := &Signer{
		KeyID: keyID,
		Key:   rk,
	}
	return s, nil
}

func (s *Signer) SignToken(claims *jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	token.Header["kid"] = s.KeyID
	return token.SignedString(s.Key)
}
