// This will become a separate package (mostyly) will be used for all service-to-service authentication
// and moving other attributes around such as groups, orgID,etc.
// Specifications: https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit#heading=h.imy018wzvh86
package ssdjwtauth

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var hmacSecret string = "test"
var adminGroups []string
var SSDTokenTypeUser string = "user/v1"
var SSDTokenTypeService string = "service-account/v1"
var SSDTokenTypeInternal string = "internal-account/v1"

var skewTimeout time.Duration
var userTokenTimeout30 time.Duration
var userTokenTimeout60 time.Duration
var userTokenTimeout90 time.Duration
var userTokenTimeout365 time.Duration
var serviceTokenTimeout time.Duration
var internalTokenTimeout time.Duration
var sessionTimeout time.Duration

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
	Type        string   `json:"type,omitempty" yaml:"type,omitempty"`       // "internal"
	Service     string   `json:"service,omitempty" yaml:"service,omitempty"` // Username that we will use for authentication
	Permissions []string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
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
	sut := &SsdUserToken{}
	sut.Uid = uid
	sut.Groups = groups
	sut.OrgID = "NoAPIAvailableYET"         // Need to call an API to get an Org of a USER??
	sut.IsAdmin = IsUserAnAdmin(sut.Groups) // Set the IsAdmin flag
	sut.Type = SSDTokenTypeUser
	// claims := getLoginClaims(sut)
	tmpDuration := sessionTimeout
	switch lifeTime {
	case 30:
		tmpDuration = userTokenTimeout30
	case 60:
		tmpDuration = userTokenTimeout60
	case 90:
		tmpDuration = userTokenTimeout90
	case 365:
		tmpDuration = userTokenTimeout365
	case 0: // Default is session Timeout
	default:
		return "", fmt.Errorf("invalid expiration option specified(0,30,60,90,365):%v", lifeTime)
	}
	claims := getBaseClaims(tmpDuration)
	claims["ssd.opsmx.io"] = sut
	claims["sub"] = sut.Uid
	return getSignedTokenStr(&claims)
}

// Create a new Service JWT and return a base64 encoded string
// Returns: token-string, nil on success or non-nil error
func CreateServiceJWT(service, instanceId, orgID string) (string, error) {
	sut := &SsdServiceToken{}
	sut.Type = SSDTokenTypeService
	sut.Service = service
	sut.InstanceID = instanceId
	sut.OrgID = orgID
	sut.Type = SSDTokenTypeService
	claims := getBaseClaims(serviceTokenTimeout)
	claims["ssd.opsmx.io"] = sut
	return getSignedTokenStr(&claims)
}

// Create a new Internal JWT and return a base64 encoded string
// Returns: token-string, nil on success or non-nil error
func CreateInternalJWT(service string, permissions []string) (string, error) {
	sut := &SsdInternalToken{}
	sut.Type = SSDTokenTypeInternal
	sut.Service = service
	sut.Permissions = permissions
	claims := getBaseClaims(internalTokenTimeout)
	claims["ssd.opsmx.io"] = sut
	return getSignedTokenStr(&claims)
}

// Method to fill in all the defaults and set the expiry time
// based on seconds provided
func getBaseClaims(duration time.Duration) jwt.MapClaims {
	log.Printf("Duration: %v", duration)
	claims := jwt.MapClaims{
		"iss": "OpsMx",
		"aud": "ssd.opsmx.io",
		"nbf": time.Now().Add(skewTimeout).Unix(),
		"exp": time.Now().Add(duration).Unix(), // JWT expiration time
		"jti": uuid.New(),
	}
	return claims
}

// Initialize JWT creation. This might include certs/secrets, admin groups and more
// Must be called before using any other methods, typically during start-up
func InitJWTSecret(secret string, admingrps []string, sessionTmout, serviceTokenTmout, internalTokenTmout uint) {
	hmacSecret = secret
	adminGroups = admingrps
	skewTimeout = -time.Duration(300) * time.Second            // Fixed time for handling clock skews, negative
	sessionTimeout = time.Duration(sessionTmout) * time.Second // Session time out in mill sec
	serviceTokenTimeout = time.Duration(serviceTokenTmout) * time.Second
	internalTokenTimeout = time.Duration(internalTokenTmout) * time.Second
	// userTokenTimeout = time.Duration(userTokenTmout) * time.Second
	userTokenTimeout30 = time.Duration(30) * time.Hour * 24
	userTokenTimeout60 = time.Duration(60) * time.Hour * 24
	userTokenTimeout90 = time.Duration(90) * time.Hour * 24
	userTokenTimeout365 = time.Duration(365) * time.Hour * 24
	// TODO: Go-routine to clean-up the revoked list once the token has expired
}

///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
////////// NO CODE BELOW THIS LINE, CUT-PASTE STUFF ONLY //////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// // Sign and get the complete encoded token as a string using the secret
// tokenString, err := token.SignedString([]byte(hmacSecret))
// if err != nil {
// 	return false, "", err
// }
// return true, tokenString, nil
// sut := SsdUserToken{
// 	Type:    SSDTokenTypeUser,
// 	Uid:     user.Uid,
// 	OrgID:   "NoAPIAvailableYET",
// 	Groups:  []string{},
// 	IsAdmin: false,
// 	JTI:     "NotImplementedYet",
// 	ExpTime: time.Time{},
// }
// sut := SsdUserToken{"user/v1", user.Uid, "NoAPIAvailableYET", user.Groups, false}
// Not using MAPs, that might be slower than a direct search as we don't expect a long list of Admin-groups
// This might be a challenge where one of our customers has 1500+ groups per user
// found := false
// for _, element := range sut.Groups { // With 3 admin groups, 1500 user groups, we have 4500 iterations!!
// 	for _, usergrp := range adminGroups {
// 		if element == usergrp {
// 			found = true
// 			break
// 		}
// 	}
// }

// claims := jwt.MapClaims{
// 	"sub": sut.Uid,
// 	"aud": "ssd.opsmx.io",
// 	"nbf": time.Now().Add(-time.Second * 300).Unix(),
// 	// "nbf":          time.Now().Unix(),
// 	"exp":          time.Now().Add(time.Second * sessionTimeout).Unix(), // JWT expiration time
// 	"jti":          uuid.New(),
// 	"ssd.opsmx.io": sut,
// }
// return getSignedTokenStr(&claims)
// claims := jwt.MapClaims{
// 	"sub": sut.Uid,
// 	"aud": "ssd.opsmx.io",
// 	"nbf": time.Now().Add(-time.Second * 300).Unix(),
// 	// "nbf":          time.Now().Unix(),
// 	"exp":          time.Now().Add(time.Second * sessionTimeout).Unix(), // JWT expiration time
// 	"jti":          uuid.New(),
// 	"ssd.opsmx.io": sut,
// }

// Structure for User Token Claim, that is created at login or via UI after logging in
// OR can be created with an existing Token before it expires
// type SsdJwtUser struct {
// 	Username string
// 	Groups   []string
// 	IsAdmin  bool
// 	JTI      string    // Token identifier
// 	ExpTime  time.Time // Expiry time, needed for clean up
// }

// func getLoginClaims(sut *SsdUserToken) *jwt.MapClaims {
// 	claims := getBaseClaims(sessionTimeout)
// 	claims["ssd.opsmx.io"] = sut
// 	claims["sub"] = sut.Uid
// 	return &claims
// }
