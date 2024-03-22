package ssdjwtauth

import (
	"fmt"
	"net/http"
	// "ssdgate/config"
)

// Middleware that check if a user is already logged in and pass it through.
// Else redirect them to login page. The login handler would set correctly based on authentication type
// Note: POSTs, if they are redirected, they get changed to GET, body is not preserved
// TODO: Add a separate logging and prometheus metrics Middleware
func JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := GetTokenStrFromHeader(r)
		_, err := GetSsdTokenFromClaims(tokenStr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintln(err)))
			return
		}
		//Token is Valid
		next.ServeHTTP(w, r)
	})
}
