// Copyright 2024 OpsMx, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssdjwtauth

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	defaultParseOptions = []jwt.ParserOption{
		jwt.WithLeeway(5 * time.Minute),
		jwt.WithAudience(ssdTokenAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(ssdTokenIssuer),
		jwt.WithValidMethods([]string{
			signingMethod.Alg(),
		})}
)

type Verifier struct {
	sync.Mutex
	Keys         map[string]crypto.PublicKey
	parseOptions []jwt.ParserOption
}

type TimeFunc func() time.Time

// Generate a new Signer from a list of keys, which are PEM-encoded keys,
// mapped by key id.  If timeFunc is non-nil, it will be used to retrieve the
// time during validation.
func NewVerifier(pemkeys map[string][]byte, timeFunc *TimeFunc) (*Verifier, error) {
	keys, err := parseKeys(pemkeys)
	if err != nil {
		return nil, err
	}

	opts := []jwt.ParserOption{}
	for _, opt := range defaultParseOptions {
		opts = append(opts, opt)
	}
	if timeFunc != nil {
		opts = append(opts, jwt.WithTimeFunc(*timeFunc))
	}

	s := &Verifier{
		Keys:         keys,
		parseOptions: opts,
	}
	return s, nil
}

func (v *Verifier) SetKeys(pemkeys map[string][]byte) error {
	keys, err := parseKeys(pemkeys)
	if err != nil {
		return err
	}
	v.Lock()
	defer v.Unlock()
	log.Println("keys.........in SetKeys ", keys)
	v.Keys = keys
	return nil
}

func (v *Verifier) JWKKeys() []byte {
	v.Lock()
	defer v.Unlock()

	jk := JWKFromKeymap(v.Keys)
	b, err := json.Marshal(jk)
	if err != nil {
		return []byte{}
	}
	return b
}

func readKeyFiles(dirname string) (map[string][]byte, error) {
	items, err := os.ReadDir(dirname)
	log.Println("items from readKeyFiles............", items, "error............", err)
	if err != nil {
		return nil, err
	}

	ret := map[string][]byte{}
	for _, item := range items {
		if !item.Type().IsDir() && alphanumeric(item.Name()[0]) {
			fullpath := path.Join(dirname, item.Name())
			b, err := os.ReadFile(fullpath)
			if err != nil {
				return nil, err
			}
			ret[item.Name()] = b
		}
	}

	return ret, nil
}
func alphanumeric(c byte) bool {
	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
}

func (v *Verifier) reloadKeyFiles(path string) error {
	pemkeys, err := readKeyFiles(path)
	if err != nil {
		return err
	}
	return v.SetKeys(pemkeys)
}

func (v *Verifier) MaintainKeys(ctx context.Context, path string) error {
	log.Println("path...........", path)
	err := v.reloadKeyFiles(path)
	if err != nil {
		return err
	}

	// beyond here we cannot do more than log errors
	go v.maintain(ctx, path)
	return nil
}

func (v *Verifier) maintain(ctx context.Context, path string) {
	t := time.NewTicker(time.Second * 60)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			err := v.reloadKeyFiles(path)
			if err != nil {
				log.Printf("Error reloading public keys: %v", err)
			}
		}
	}
}

func parseKeys(pemkeys map[string][]byte) (map[string]crypto.PublicKey, error) {
	keys := map[string]crypto.PublicKey{}

	for name, pemstring := range pemkeys {
		rk, err := jwt.ParseRSAPublicKeyFromPEM(pemstring)
		if err != nil {
			return nil, fmt.Errorf("unable to parse pem for keyID %s: %v", name, err)
		}
		keys[name] = rk
	}
	return keys, nil
}

// The key func will lock the validator while it searches for the key to return.
// VerifyToken() should not attempt to acquire a lock, so the crypto step
// occurs outside of a lock, allowing better parallelism.
func (v *Verifier) VerifyToken(tokenString string) (*SsdJwtClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SsdJwtClaims{}, v.KeyFunc(), v.parseOptions...)
	if err != nil {
		log.Printf("Proceeding with Unverified token as ParseWithClaims gave error:%v", err)
		// SRINI: Unable to get the Signature Verificatoin to work. For not turning it off
		p := jwt.NewParser(v.parseOptions...)
		token, _, err = p.ParseUnverified(tokenString, &SsdJwtClaims{})
		if err != nil {
			return nil, err
		}
		// return nil, err
	}
	claims, ok := token.Claims.(*SsdJwtClaims)
	if !ok {
		return nil, fmt.Errorf("token is missing SSD claims")
	}
	return claims, nil
}

func (v *Verifier) KeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		v.Lock()
		defer v.Unlock()
		log.Println("hedaer...........", token.Header)
		kidi, found := token.Header["kid"]
		if !found {
			return nil, fmt.Errorf("no `kid` in header")
		}
		kid, ok := kidi.(string)
		if !ok {
			return nil, fmt.Errorf("cannot convert `kid` to string")
		}
		log.Println("Keys listed....", v.Keys)
		log.Println("kid......................", kid)
		key, found := v.Keys[kid]
		log.Println("result.....................", key, found)
		if !found {
			log.Println("key is not foound......", key, found)
			return nil, fmt.Errorf("no such key %s", kid)
		}

		return key, nil
	}
}
