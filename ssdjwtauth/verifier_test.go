package ssdjwtauth

import (
	"log"
	"net/http"
	"testing"
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
