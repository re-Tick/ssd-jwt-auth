// This will become a separate package (mostyly) will be used for all service-to-service authentication
// and moving other attributes around such as groups, orgID,etc.
// Specifications: https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit#heading=h.imy018wzvh86
package ssdjwtauth

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
)

// Get User Token Claim from token string
func GetSsdUserToken(m *map[string]interface{}) (*SsdUserToken, error) {
	tokenType, _ := (*m)["type"].(string)
	if tokenType != SSDTokenTypeUser {
		return nil, fmt.Errorf("not user type SSDToken")
	}
	sut := SsdUserToken{}
	err := mapstructure.Decode(m, &sut)
	if err != nil {
		return nil, err
	}
	return &sut, nil
}

// Get Service Token Claim from token string
func GetSsdServiceToken(m *map[string]interface{}) (*SsdServiceToken, error) {
	tokenType, _ := (*m)["type"].(string)
	if tokenType != SSDTokenTypeService {
		return nil, fmt.Errorf("not Service type SSDToken")
	}
	sut := SsdServiceToken{}
	err := mapstructure.Decode(m, &sut)
	if err != nil {
		return nil, err
	}
	return &sut, nil
}

// Get Service Token Claim from token string
func GetSsdInternalToken(m *map[string]interface{}) (*SsdInternalToken, error) {
	tokenType, _ := (*m)["type"].(string)
	if tokenType != SSDTokenTypeInternal {
		return nil, fmt.Errorf("not Internal type SSDToken")
	}
	sut := SsdInternalToken{}
	err := mapstructure.Decode(m, &sut)
	if err != nil {
		log.Printf("Error Parsing UserToken:%v", err)
		return nil, err
	}
	return &sut, nil
}

// Look for Authorization header(s) and see if we can get the token String
func GetTokenStrFromHeader(r *http.Request) string {
	var tokenStr string
	auth := r.Header.Get("Authorization")
	if auth == "" {
		auth = r.Header.Get("X-OpsMx-Auth") // If the header is not Authorization, check X-OpsMx-Auth
		if auth == "" {
			return ""
		}
		tokenStr = auth // if X-OpsMx-Auth is there, there is no "Bearer" type
	} else {
		splitToken := strings.Split(auth, "Bearer ")
		tokenStr = splitToken[1]
	}
	return tokenStr
}

// Get Uid from Incoming Request
func GetUserFromReqHeader(r *http.Request) (string, error) {
	tokenStr := GetTokenStrFromHeader(r)
	token, err := jwt.ParseWithClaims(tokenStr, &SsdJwtClaims{}, keyFunc, parseOptions...)
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*SsdJwtClaims); ok && token.Valid {
		if claims.Subject != "" {
			return claims.Subject, nil
		}
	}
	return "", fmt.Errorf("%v is not valid, has unexpected claims or Username is empty", token.Claims)
}

// Method to Valid the token, extract Claims, check that its a Valid Type
// And return it for further processing SsdToken
// func getSsdTokenFromClaims(tokenStr string) (*SsdToken, error) {
func GetSsdTokenFromClaims(tokenStr string) (*map[string]interface{}, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &SsdJwtClaims{}, keyFunc, parseOptions...)
	if err != nil {
		return nil, err
	}
	// Check if Valid
	if !token.Valid {
		return nil, fmt.Errorf("JWT token is not valid")
	}

	if claims, ok := token.Claims.(*SsdJwtClaims); ok {
		st := claims.SSDToken

		tokenType, ok := st["type"].(string)
		if !ok {
			return nil, fmt.Errorf("SSD token is does not appear to contain \"Type\"")
		}
		switch tokenType {
		case SSDTokenTypeUser:
			return &st, nil
		case SSDTokenTypeService:
			return &st, nil
		case SSDTokenTypeInternal:
			return &st, nil
		default:
			return nil, fmt.Errorf("SSD token has unsupported type:%s", tokenType)
		}
	}
	return nil, fmt.Errorf("SSD token not found in the JWT claims")
}

///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
////////// NO CODE BELOW THIS LINE, CUT-PASTE STUFF ONLY //////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////

// func createSignedToken(sut *jwt.MapClaims) (bool, string, error) {
// 	claims := jwt.MapClaims{
// 		"sub":          user.Username,
// 		"aud":          "ssd.opsmx.io",
// 		"nbf":          time.Now().Unix(),
// 		"exp":          time.Now().Add(time.Hour * 24).Unix(), // JWT expiration time
// 		"jti":          uuid.New(),
// 		"ssd.opsmx.io": sut,
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

// 	// Sign and get the complete encoded token as a string using the secret
// 	tokenString, err := token.SignedString([]byte(hmacSecret))
// 	if err != nil {
// 		return false, "", err
// 	}
// 	return true, tokenString, nil
// }

// Check if the JWT is valid, get the claims.
// // true if JWT is valid, string contains the claims
// func verifyJWT(tokenStr string) (jwt.MapClaims, error) {
// 	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
// 		// Don't forget to validate the alg is what you expect:
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return hmacSecret, nil
// 	})

// 	if err != nil {
// 		log.Println(err)
// 	}

// 	if claims, ok := token.Claims.(jwt.MapClaims); ok {
// 		return claims, nil
// 		// fmt.Println(claims["foo"], claims["nbf"])
// 	}
// 	return nil, nil
// }

// // Method to check if JWT is present in the headers
// // if true, it is processed. Return username if present
// // or error if the JWT is not proper
// func GetJWTUser(r http.Request) (bool, string, error) {
// 	tokenStr := getTokenStrFromHeader(r)
// 	if tokenStr == "" {
// 		return false, "", nil
// 	}
// 	claims, err := verifyJWT(tokenStr)
// 	if err != nil {
// 		// user, ok
// 		return false, "", nil
// 	}
// 	usr := claims["username"].(string)
// 	return false, usr, nil
// }
// type SsdToken interface { // Interface to return any type of SSD Token
// 	GetTokenType() string
// }

// func (s *SsdUserToken) GetTokenType() string {
// 	return s.Type
// }
// func (s *SsdServiceToken) GetTokenType() string {
// 	return s.Type
// }
// func (s *SsdInternalToken) GetTokenType() string {
// 	return s.Type
// }
//
//	func GetSsdServiceTokenFromStr(tokenStr string) (*SsdServiceToken, error) {
//		m, err := GetSsdTokenFromClaims(tokenStr)
//
//	if err != nil {
//		return nil, err
//	}
