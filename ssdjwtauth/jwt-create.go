// This will become a separate package (mostyly) will be used for all service-to-service authentication
// and moving other attributes around such as groups, orgID,etc.
// Specifications: https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit#heading=h.imy018wzvh86
package ssdjwtauth

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	adminGroups          []string
	SSDTokenTypeUser     string = "user/v1"
	SSDTokenTypeService  string = "service-account/v1"
	SSDTokenTypeInternal string = "internal-account/v1"

	serviceTokenTimeout  time.Duration
	internalTokenTimeout time.Duration
	sessionTimeout       time.Duration
)

// Structure for User Token Claims that can be created via UI, or via API with a valid token
type SsdUserToken struct {
	Type    string   `json:"type"`          // can be "user" or "serviceAccount"
	Uid     string   `json:"uid,omitempty"` //Username that we will use for authentication
	OrgID   string   `json:"orgId,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	IsAdmin bool     `json:"isAdmin"`
}

// Structure for Service Token Claims that can be created via UI, or via API with a valid token
type SsdServiceToken struct {
	Type       string `json:"type"`            // can be "user" or "serviceAccount"
	Service    string `json:"service"`         // Name of the Service (e.g. Jenkins) that we will use for authentication
	InstanceID string `json:"instId"`          // Instance of Service (which Jenkins are we talking about), Need API for this
	OrgID      string `json:"orgId,omitempty"` // Organization ID, Need API for this
}

// Structure for Internal Token used for service-to-service communication. Any of the services
// Can create these at any time.
type SsdInternalToken struct {
	Type           string   `json:"type,omitempty" yaml:"type,omitempty"`       // "internal"
	Service        string   `json:"service,omitempty" yaml:"service,omitempty"` // Username that we will use for authentication
	Authorizations []string `json:"authorizations,omitempty" yaml:"authorizations,omitempty"`
}

// JWT structure including Standard claims (renamed as registered claims)
type SsdJwtClaims struct {
	SSDToken map[string]interface{} `json:"ssd.opsmx.io"`
	jwt.RegisteredClaims
}

// All token types implement this interface
type SSDToken interface {
	GetTokenType() string
	IsAdminToken() bool
}

// Interface to get a type, without know what that type is
func (t SsdUserToken) GetTokenType() string {
	return t.Type
}
func (t SsdServiceToken) GetTokenType() string {
	return t.Type
}

func (t SsdInternalToken) GetTokenType() string {
	return t.Type
}

func (t SsdUserToken) IsAdminToken() bool {
	return t.IsAdmin
}

func (t SsdServiceToken) IsAdminToken() bool {
	return false // In Service Token, there is NO admin or not-admin, they are never admins
}

func (t SsdInternalToken) IsAdminToken() bool {
	return true // Always true for internal tokens
}

// Create a new JWT and return a base64 encoded string.
// lifeTime legitimate values are: 30, 60, 90 and 365 days. 0 = Session Token, based on session Timeout value
// Returns: token-string, nil on success or non-nil error
func CreateUserJWT(uid string, groups []string, lifeTime uint) (string, error) {
	sut := &SsdUserToken{
		Type:    SSDTokenTypeUser,
		Uid:     uid,
		Groups:  groups,
		OrgID:   "notset",
		IsAdmin: IsUserAnAdmin(groups),
	}
	// claims := getLoginClaims(sut)
	claims := getBaseClaims(time.Duration(lifeTime) * time.Second)
	claims[customClaimName] = sut
	claims["sub"] = sut.Uid
	return getSignedTokenStr(&claims, SigningKey)
}

// Create a new Service JWT and return a base64 encoded string
// Returns: token-string, nil on success or non-nil error
func CreateServiceJWT(service, instanceId, orgID string) (string, error) {
	sut := &SsdServiceToken{
		Type:       SSDTokenTypeService,
		Service:    service,
		InstanceID: instanceId,
		OrgID:      orgID,
	}
	claims := getBaseClaims(serviceTokenTimeout)
	claims[customClaimName] = sut
	return getSignedTokenStr(&claims, SigningKey)
}

// Create a new Internal JWT and return a base64 encoded string
// Returns: token-string, nil on success or non-nil error
func CreateInternalJWT(service string, authorizations []string) (string, error) {
	sut := &SsdInternalToken{
		Type:           SSDTokenTypeInternal,
		Service:        service,
		Authorizations: authorizations,
	}
	claims := getBaseClaims(internalTokenTimeout)
	claims[customClaimName] = sut
	return getSignedTokenStr(&claims, SigningKey)
}

// Method to fill in all the defaults and set the expiry time
// based on seconds provided
func getBaseClaims(duration time.Duration) jwt.MapClaims {
	log.Printf("Duration: %v", duration)
	claims := jwt.MapClaims{
		"iss": customIssuer,
		"aud": customAudience,
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(duration).Unix(), // JWT expiration time
		"jti": uuid.New(),
	}
	return claims
}

// Initialize JWT creation. This might include certs/secrets, admin groups and more
// Must be called before using any other methods, typically during start-up
func InitJWTSecret(admingrps []string, sessionTmout, serviceTokenTmout, internalTokenTmout uint) {
	adminGroups = admingrps
	sessionTimeout = time.Duration(sessionTmout) * time.Second // Session time out in mill sec
	serviceTokenTimeout = time.Duration(serviceTokenTmout) * time.Second
	internalTokenTimeout = time.Duration(internalTokenTmout) * time.Second
	// userTokenTimeout = time.Duration(userTokenTmout) * time.Second
	// TODO: Go-routine to clean-up the revoked list once the token has expired
}
