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
	"net/http"
	"strings"
)

type ssdContextKeyType int

var (
	ssdContextKey      ssdContextKeyType = 0
	ssdTokenContextKey ssdContextKeyType = 1
)

func (v *Verifier) MiddlewareFunc() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := TokenFromHeaders(r)
			claims, err := v.VerifyToken(tokenStr)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
				return
			}
			r = r.WithContext(contextWithToken(r.Context(), claims, tokenStr))
			next.ServeHTTP(w, r)
		})
	}
}

func contextWithToken(ctx context.Context, claims *SsdJwtClaims, token string) context.Context {
	ctx = context.WithValue(ctx, ssdContextKey, claims)
	ctx = context.WithValue(ctx, ssdTokenContextKey, token)
	return ctx
}

func SSDClaimsFromContext(ctx context.Context) (*SsdJwtClaims, bool) {
	v, ok := ctx.Value(ssdContextKey).(*SsdJwtClaims)
	return v, ok
}

func SSDTokenFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ssdTokenContextKey).(string)
	return v, ok
}

func TokenFromHeaders(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		auth = r.Header.Get("X-OpsMx-Auth")
	}
	if auth == "" {
		return ""
	}
	splitToken := strings.Split(auth, "Bearer ")
	if len(splitToken) < 2 {
		return "Header does not contain TOKEN"
	}
	return splitToken[1]
}
