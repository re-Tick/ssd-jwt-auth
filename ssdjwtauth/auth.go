package ssdjwtauth

import (
	"github.com/golang-jwt/jwt/v5"
)

const (
	customClaimName  = "ssd.opsmx.io"
	ssdTokenAudience = "ssd.opsmx.io"
	ssdTokenIssuer   = "OpsMx"

	SSDTokenTypeUser     = "user/v1"
	SSDTokenTypeService  = "service-account/v1"
	SSDTokenTypeInternal = "internal-account/v1"
)

type SsdJwtClaims struct {
	jwt.RegisteredClaims
	SSDCLaims SSDClaims `json:"ssd.opsmx.io"`
}

type SSDClaims struct {
	Type string
}
