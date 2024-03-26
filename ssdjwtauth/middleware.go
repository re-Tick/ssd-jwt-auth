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
			tokenStr := tokenFromHeaders(r)
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

func tokenFromHeaders(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		auth = r.Header.Get("X-OpsMx-Auth")
	}
	if auth == "" {
		return ""
	}
	splitToken := strings.Split(auth, "Bearer ")
	return splitToken[1]
}
