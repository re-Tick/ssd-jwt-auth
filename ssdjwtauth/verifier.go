package ssdjwtauth

import (
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	Keys map[string]crypto.PublicKey
}

// Generate a new Signer from a list of keys, which are PEM-encoded keys,
// mapped by key id.
func NewVerifier(pemkeys map[string][]byte) (*Verifier, error) {
	keys := map[string]crypto.PublicKey{}

	for name, pemstring := range pemkeys {
		rk, err := jwt.ParseRSAPublicKeyFromPEM(pemstring)
		if err != nil {
			return nil, fmt.Errorf("unable to parse pem for keyID %s: %v", name, err)
		}
		keys[name] = rk
	}
	s := &Verifier{
		Keys: keys,
	}
	return s, nil
}

func (v *Verifier) KeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kidi, found := token.Header["kid"]
		if !found {
			return nil, fmt.Errorf("no `kid` in header")
		}
		kid, ok := kidi.(string)
		if !ok {
			return nil, fmt.Errorf("cannot convert `kid` to string")
		}
		key, found := v.Keys[kid]
		if !found {
			return nil, fmt.Errorf("no such key %s", kid)
		}
		return key, nil
	}
}
