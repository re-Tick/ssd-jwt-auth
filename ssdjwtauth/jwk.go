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
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"log"
	"math/big"
)

type JWK struct {
	E   string `json:"e,omitempty" yaml:"e,omitempty"`
	N   string `json:"n,omitempty" yaml:"n,omitempty"`
	KTY string `json:"kty,omitempty" yaml:"kty,omitempty"`
	KID string `json:"kid,omitempty" yaml:"kid,omitempty"`
	ALG string `json:"alg,omitempty" yaml:"alg,omitempty"`
	USE string `json:"use,omitempty" yaml:"use,omitempty"`
}

type JWKWrapper struct {
	Keys []JWK `json:"keys,omitempty" yaml:"keys,omitempty"`
}

func JWKFromKeymap(keys map[string]crypto.PublicKey) JWKWrapper {
	jk := []JWK{}

	for id, pubkey := range keys {
		rsakey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			log.Printf("Key is not a public key, ignoring")
			continue
		}
		e64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsakey.E)).Bytes())
		n64 := base64.RawURLEncoding.EncodeToString(rsakey.N.Bytes())
		j := JWK{
			KTY: "RSA",
			ALG: signingMethod.Alg(),
			USE: "sig",
			KID: id,
			E:   e64,
			N:   n64,
		}
		jk = append(jk, j)
	}
	return JWKWrapper{
		Keys: jk,
	}
}
