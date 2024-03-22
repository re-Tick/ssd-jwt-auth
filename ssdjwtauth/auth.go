package ssdjwtauth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	customClaimName = "ssd.opsmx.io"
	customAudience  = "ssd.opsmx.io"
	customIssuer    = "OpsMx"
)

var (
	parseOptions = []jwt.ParserOption{
		jwt.WithLeeway(5 * time.Minute),
		jwt.WithAudience(customAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(customIssuer),
		jwt.WithValidMethods([]string{
			jwt.SigningMethodPS256.Name,
		})}
)

type SsdJwtClaims struct {
	jwt.RegisteredClaims
	SSDCLaims SSDClaims `json:"ssd.opsmx.io"`
}

type SSDClaims struct {
	Type string
}
