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
	signer = jwt.SigningMethodPS256

	parseOptions = []jwt.ParserOption{
		jwt.WithLeeway(5 * time.Minute),
		jwt.WithAudience(customAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(customIssuer),
		jwt.WithValidMethods([]string{
			signer.Name,
		})}
)
