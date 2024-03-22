// This ssdjwtauth package (mostyly) is be used for all service-to-service authentication
// and moving other attributes around such as groups, orgID,etc.
// Specifications: https://docs.google.com/document/d/1uuKitg7G0m6GzXM0BYzbsyEogZeUhthy7LSUTgnRtuQ/edit#heading=h.imy018wzvh86
// We have jwt-create.go - create various types of JWTs, auth.go - methods other services can call
// This main program is meant to test and also give examples of usage of the token creation and decoding

package main

import (
	"log"

	"github.com/OpsMx/ssd-jwt-auth/ssdjwtauth"
)

// Pre-generated Token strings for testing, could expire after month or so, but are overwritten by createTokens
var uTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzc2Qub3BzbXguaW8iLCJleHAiOjE3MDY5OTAwNDEsImlzcyI6Ik9wc014IiwianRpIjoiZTc1OGZkYTktNDQxNC00YWEwLTkyODQtYjVjNWZmY2NlNmI5IiwibmJmIjoxNzA2OTg2MTQxLCJzc2Qub3BzbXguaW8iOnsidHlwZSI6InVzZXIvdjEiLCJ1aWQiOiJrc3JpbmltYmEiLCJvcmdJZCI6Ik5vQVBJQXZhaWxhYmxlWUVUIiwiZ3JvdXBzIjpbImRldiIsInFhIl0sImlzQWRtaW4iOmZhbHNlfSwic3ViIjoia3NyaW5pbWJhIn0.OTpkfM6crN3iJzY6393y6JpQIEKgycMxUuUnEuj097M"
var sTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzc2Qub3BzbXguaW8iLCJleHAiOjE3MDk1Nzg0NDEsImlzcyI6Ik9wc014IiwianRpIjoiNjk4MmU5ZDItNGY0YS00MzBjLThmYjgtYTE4NWFkNjc1OWI0IiwibmJmIjoxNzA2OTg2MTQxLCJzc2Qub3BzbXguaW8iOnsidHlwZSI6InNlcnZpY2UtYWNjb3VudC92MSIsInNlcnZpY2UiOiJqZW5raW5zIiwiaW5zdElkIjoiNDU2Nzg5Iiwib3JnSWQiOiJOb0FQSUF2YWlsYWJsZVlFVCJ9fQ.lMYgIjrzwvGk_6YewOVUacUz5xYFfmP5SKEBERNcHjE"
var iTokenStr string = "bugus" // This is updated when created, so it would not expire

// Invalid Token strings, need to think of more failure cases
var iTokenExpiredStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzc2Qub3BzbXguaW8iLCJleHAiOjE3MDY5ODY0NzEsImlzcyI6Ik9wc014IiwianRpIjoiMzE4NjkyZWMtMDE4YS00NGQ4LTg5ZGUtNDBhOWMzOWZlYmIzIiwibmJmIjoxNzA2OTg2MTQxLCJzc2Qub3BzbXguaW8iOnsidHlwZSI6ImludGVybmFsLWFjY291bnQvdjEiLCJzZXJ2aWNlIjoic3NkLW9wYSIsImlzQWRtaW4iOnRydWV9fQ.Ow9eWgaxUPVRx6iLHAzsGdJvEyzEu59EPx1OEvl0pBg"
var wrongAudTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJXcm9uZ0FVRCIsImV4cCI6MTcwNjk5MDIzMCwiaXNzIjoiT3BzTXgiLCJqdGkiOiIyZmM5OGEwNS01MTY2LTQzYzctOGQwZC03Y2YxZmQzNGRhYjciLCJuYmYiOjE3MDY5ODYzMzAsInNzZC5vcHNteC5pbyI6eyJ0eXBlIjoidXNlci92MSIsInVpZCI6ImtzcmluaW1iYSIsIm9yZ0lkIjoiTm9BUElBdmFpbGFibGVZRVQiLCJncm91cHMiOlsiZGV2IiwicWEiXSwiaXNBZG1pbiI6ZmFsc2V9LCJzdWIiOiJrc3JpbmltYmEifQ.dO-jlGLA3GxOH7Erd_dajF5D0cWrxy9mFjrB3kmfD9M"
var wrongIssuerTokenStr string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzc2Qub3BzbXguaW8iLCJleHAiOjE3MDY5OTA0ODMsImlzcyI6Ildyb25nSVNTIiwianRpIjoiMDg4ZjcwOWEtYzEwZi00ZGQ5LTliNTctNzkxNzgxZDc1YjQ1IiwibmJmIjoxNzA2OTg2NTgzLCJzc2Qub3BzbXguaW8iOnsidHlwZSI6InVzZXIvdjEiLCJ1aWQiOiJrc3JpbmltYmEiLCJvcmdJZCI6Ik5vQVBJQXZhaWxhYmxlWUVUIiwiZ3JvdXBzIjpbImRldiIsInFhIl0sImlzQWRtaW4iOmZhbHNlfSwic3ViIjoia3NyaW5pbWJhIn0.QOc4zViMBcfRa_tQTVC8H8KigvP2QA9eGokbIr-zeWI"

func main() { // TODO: change to a demo/test method
	// Initialize: userID, adminGroups, UI session expiry, serviceAccount expiry, internal Token expiry time
	// TODO: Replace HMAC with cert+key
	ssdjwtauth.InitJWTSecret([]string{"admin", "bigboss"}, 3600, 3600*24*30, 30)
	create3TypeOfTokens()
	testUserInfoFromSSDToken(uTokenStr)
	testServiceInfoFromSSDToken(sTokenStr)
	// testServiceInfo(sTokenStr)
	// Now to Decode and get info
	// Failure test-cases: create tokens with wrong issuer??
}

func decode3TypeOfTokens() {
	// Call Wrong Type call, the only error case once parsing is complete
	m, err := ssdjwtauth.GetSsdTokenFromClaims(uTokenStr)
	if err != nil {
		log.Printf("This SHOULD NOT HAPPEN: Error processing user token:%v", err)
	} else {
		_, err = ssdjwtauth.GetSsdServiceToken(m) // Service Token for User TOken
		if err != nil {
			log.Printf("Expected Error: %v", err)
		}
	}
	// All my tokens
	tStrings := []string{iTokenExpiredStr, wrongIssuerTokenStr, wrongAudTokenStr, uTokenStr, sTokenStr, iTokenStr}
	for i, s := range tStrings {
		// log.Printf("%v, %v", i, s)
		m, err := ssdjwtauth.GetSsdTokenFromClaims(s)
		if err != nil {
			log.Printf("Expected Error(0,1,2):Token no.:%d:%v", i, err)
			continue
		}
		tokenType := (*m)["type"].(string)
		switch tokenType {
		case ssdjwtauth.SSDTokenTypeUser:
			sut, err := ssdjwtauth.GetSsdUserToken(m)
			log.Printf("Valid User Token:%+v:Error=%v", sut, err)
			// return sut
		case ssdjwtauth.SSDTokenTypeService:
			sut, err := ssdjwtauth.GetSsdServiceToken(m)
			log.Printf("Valid Service Token:%+v:Error=%v", sut, err)
			// return sut
		case ssdjwtauth.SSDTokenTypeInternal:
			sut, err := ssdjwtauth.GetSsdInternalToken(m)
			log.Printf("Valid User Token:%+v:Error=%v", sut, err)
			// return sut
		}
	}
}

// Create and print 3 types of tokens
func create3TypeOfTokens() {
	log.Println("use jwt.io, debugger to see the token, epochconverter.com to check the expiry")
	// Create tokens of each type - user
	var err error
	uTokenStr, err = ssdjwtauth.CreateUserJWT("OpsMx", []string{"dev", "qa"}, 365)
	if err != nil {
		log.Printf("User Token Creation Error:%v", err)
	} else {
		// take the token strings and decode and print contents
		log.Printf("User Token Created: %s", uTokenStr)
	}

	// Create tokens of each type - Service
	sTokenStr, err = ssdjwtauth.CreateServiceJWT("jenkins", "456789", "NoAPIAvailableYET")
	if err != nil {
		log.Printf("Service Token Creation Error:%v", err)
	} else {
		// take the token strings and decode and print contents
		log.Printf("Service Token Created: %s", sTokenStr)
	}

	// Create tokens of each type - Internal
	iTokenStr, err = ssdjwtauth.CreateInternalJWT("ssd-opa", []string{"perm1", "perm2"})
	if err != nil {
		log.Printf("Internal Token Creation Error:%v", err)
	} else {
		// take the token strings and decode and print contents
		log.Printf("Internal Token Created: %s", iTokenStr)
	}
}

func testUserInfo(tokenStr string) {
	uid, groups, orgId, isAdmin, err := ssdjwtauth.GetUserTokenInfo(tokenStr)
	log.Printf("User ID: %s", uid)
	log.Printf("User Groups: %v", groups)
	log.Printf("User orgId: %s", orgId)
	log.Printf("User isAdmin: %v", isAdmin)
	log.Printf("Error: %v", err)
}

func testServiceInfo(tokenStr string) {
	sr, inst, orgId, err := ssdjwtauth.GetServiceTokenInfo(tokenStr)
	log.Printf("Service: %s", sr)
	log.Printf("Instance: %v", inst)
	log.Printf("User orgId: %s", orgId)
	log.Printf("Error: %v", err)
}

func testServiceInfoFromSSDToken(tokenStr string) {
	tok, err := ssdjwtauth.DecodeToken(tokenStr)
	if err != nil {
		log.Println("We are screwed")
		return
	}
	if tok.GetTokenType() != ssdjwtauth.SSDTokenTypeService {
		log.Println("We were expecting a ServiceToken but apparently it is not")
		return
	}
	sr, inst, orgId, err := ssdjwtauth.GetServiceInfoFromSSDToken(tok)
	log.Printf("Service: %s", sr)
	log.Printf("Instance: %v", inst)
	log.Printf("User orgId: %s", orgId)
	log.Printf("Error: %v", err)
}

func testUserInfoFromSSDToken(tokenStr string) {
	tok, err := ssdjwtauth.DecodeToken(tokenStr)
	if err != nil {
		log.Println("We are screwed")
		return
	}
	if tok.GetTokenType() != ssdjwtauth.SSDTokenTypeUser {
		log.Println("We were expecting a ServiceToken but apparently it is not")
		return
	}
	uid, groups, orgId, isAdmin, err := ssdjwtauth.GetUserInfoFromSSDToken(tok)
	log.Printf("User ID: %s", uid)
	log.Printf("User Groups: %v", groups)
	log.Printf("User orgId: %s", orgId)
	log.Printf("User isAdmin: %v", isAdmin)
	log.Printf("Error: %v", err)
}
