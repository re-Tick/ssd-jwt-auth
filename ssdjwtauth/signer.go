package ssdjwtauth

import (
	"crypto"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	sync.Mutex
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

func (s *Signer) MakeClaims(now time.Time, expiry time.Time, id string, ssd SSDClaims) SsdJwtClaims {
	return SsdJwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ssdTokenIssuer,
			Audience:  []string{ssdTokenAudience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
			ID:        id,
		},
		SSDCLaims: ssd,
	}
}

func (s *Signer) SetSigningKey(keyID string, pemkey []byte) error {
	rk, err := jwt.ParseRSAPrivateKeyFromPEM(pemkey)
	if err != nil {
		return fmt.Errorf("unable to parse private key PEM for keyid %s: %v", keyID, err)
	}
	s.Lock()
	defer s.Unlock()
	s.KeyID = keyID
	s.Key = rk
	return nil
}

func (s *Signer) SignToken(claims SsdJwtClaims) (string, error) {
	token := jwt.NewWithClaims(signingMethod, claims)

	s.Lock()
	defer s.Unlock()
	token.Header["kid"] = s.KeyID
	return token.SignedString(s.Key)
}
