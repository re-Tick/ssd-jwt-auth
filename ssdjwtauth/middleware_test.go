package ssdjwtauth

import (
	"context"
	"log"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func requestWithHeaders(headers map[string]string) *http.Request {
	r, err := http.NewRequest("GET", "foo", nil)
	if err != nil {
		log.Fatalln(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func Test_tokenFromHeaders(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"no auth set",
			args{
				r: requestWithHeaders(map[string]string{}),
			},
			"",
		},
		{
			"authorization header only",
			args{
				r: requestWithHeaders(map[string]string{"authorization": "Bearer foo"}),
			},
			"foo",
		},
		{
			"x-opsmx-auth header",
			args{
				r: requestWithHeaders(map[string]string{"x-opsmx-auth": "Bearer foo"}),
			},
			"foo",
		},
		{
			"prefers authorization header",
			args{
				r: requestWithHeaders(map[string]string{"authorization": "Bearer foo", "x-opsmx-auth": "bar"}),
			},
			"foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tokenFromHeaders(tt.args.r); got != tt.want {
				t.Errorf("tokenFromHeaders() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_contextWithToken(t *testing.T) {
	claims := &SsdJwtClaims{
		jwt.RegisteredClaims{
			Issuer: "testissuer",
		},
		SSDClaims{},
	}
	token := "token goes here"
	ctx := contextWithToken(context.Background(), claims, token)

	// ensure token is in the context
	t.Run("enture token", func(t *testing.T) {
		got, found := SSDTokenFromContext(ctx)
		if !found {
			t.Errorf("SSDTokenFromContext says token was not found")
		}
		if got != token {
			t.Errorf("expected token %s, got %s", token, got)
		}
	})

	t.Run("claims from token", func(t *testing.T) {
		got, found := SSDClaimsFromContext(ctx)
		if !found {
			t.Errorf("SSDClaimsFromContext says token was not found")
		}
		if got.Issuer != "testissuer" {
			t.Errorf("expected issuer to be %s, but it was %s", claims.Issuer, got.Issuer)
		}
	})

	// now ensure that we don't find either if they are not set

	t.Run("returns found properly", func(t *testing.T) {
		_, found := SSDTokenFromContext(context.Background())
		if found {
			t.Errorf("SSDTokenFromContext(context.Background()): expected found to be false")
		}
		_, found = SSDClaimsFromContext(context.Background())
		if found {
			t.Errorf("SSDClaimsFromContext(context.Background()): expected found to be false")
		}
	})
}
