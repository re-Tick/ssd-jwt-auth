// Utilities for JWT functions
package ssdjwtauth

import (
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"
)

// Given user groups and admin groups, return true if user is an Admin
func IsUserAnAdmin(userGroups []string) bool {
	found := false
	for _, element := range userGroups { // With 3 admin groups, 1500 user groups, we have 4500 iterations!!
		for _, usergrp := range adminGroups {
			if element == usergrp {
				found = true
				break
			}
		}
	}
	return found
}

// Given a token, knowning it is a UserToken, call this method to get the details
// If we don't know the token type, best is call DecodeToken, tok.GetTokenType() and call the
// appropriate "*InfoFromSSDToken" method
func GetUserTokenInfo(tokenStr string) (username string, groups []string, orgId string, isAdmin bool, err error) {
	tok, err := DecodeToken(tokenStr)
	if err != nil {
		return "", nil, "", false, err
	}
	sut, ok := tok.(*SsdUserToken)
	if !ok {
		if !ok {
			// return "", "", "", fmt.Errorf("token is not a Service Token:%s", tokenStr)
			return "", nil, "", false, fmt.Errorf("token is not a User Token: %s", tokenStr)
		}
	}
	return sut.Uid, sut.Groups, sut.OrgID, sut.IsAdmin, nil
}

// Given a token, knowning it is a ServiceToken, call this method to get the details
// If we don't know the token type, best is call DecodeToken, tok.GetTokenType() and call the
// appropriate "*InfoFromSSDToken" method
func GetServiceTokenInfo(tokenStr string) (serviceName, instanceId, orgId string, err error) {
	tok, err := DecodeToken(tokenStr)
	if err != nil {
		return "", "", "", err
	}
	sut, ok := tok.(*SsdServiceToken)
	if !ok {
		if !ok {
			return "", "", "", fmt.Errorf("token is not a Service Token: %s", tokenStr)
		}
	}
	return sut.Service, sut.InstanceID, sut.OrgID, nil
}

// Given a token, knowning it is a InternalToken, call this method to get the details
// If we don't know the token type, best is call DecodeToken, tok.GetTokenType() and call the
// appropriate "*InfoFromSSDToken" method
func GetInternalTokenInfo(tokenStr string) (serviceName string, authorizations []string, err error) {
	tok, err := DecodeToken(tokenStr)
	if err != nil {
		return "", nil, err
	}
	sut, ok := tok.(*SsdInternalToken)
	if !ok {
		if !ok {
			return "", nil, fmt.Errorf("token is not a Internal Token: %s", tokenStr)
		}
	}
	return sut.Service, sut.Authorizations, nil
}

// Given a token, call DecodeToken, call GetTokenType() and call this method if it is of type User
// To get the details
func GetUserInfoFromSSDToken(tok SSDToken) (username string, groups []string, orgId string, isAdmin bool, err error) {
	sut, ok := tok.(*SsdUserToken)
	if !ok {
		if !ok {
			// return "", "", "", fmt.Errorf("token is not a Service Token:%s", tokenStr)
			return "", nil, "", false, fmt.Errorf("token is not a User Token")
		}
	}
	return sut.Uid, sut.Groups, sut.OrgID, sut.IsAdmin, nil
}

// Given a token, call DecodeToken, call GetTokenType() and call this method if it is of type Service
// To get the details
func GetServiceInfoFromSSDToken(tok SSDToken) (serviceName, instanceId, orgId string, err error) {
	sut, ok := tok.(*SsdServiceToken)
	if !ok {
		if !ok {
			return "", "", "", fmt.Errorf("token is not a Service Token")
		}
	}
	return sut.Service, sut.InstanceID, sut.OrgID, nil
}

// Given a token, call DecodeToken, call GetTokenType() and call this method if it is of type Internal
// To get the details
func GetInternalInfoFromSSDToken(tok SSDToken) (serviceName string, authorizations []string, err error) {
	sut, ok := tok.(*SsdInternalToken)
	if !ok {
		if !ok {
			return "", nil, fmt.Errorf("token is not a Internal Token")
		}
	}
	return sut.Service, sut.Authorizations, nil
}

// Given ANY tokenStr, decode it and return "SSDToken" interface that allows us to get the "type"
// Expected usage is: call this method, get the type and call the appropriate "InfoFromSSDToken" method
func DecodeToken(tokenStr string) (SSDToken, error) {
	m, err := GetSsdTokenFromClaims(tokenStr)
	if err != nil {
		log.Printf("This SHOULD NOT HAPPEN: Error processing user token:%v", err)
		return nil, err
	}
	tokenType, ok := (*m)["type"].(string)
	if !ok {
		return nil, fmt.Errorf("token type could not be found in the tokenString")
	}
	switch tokenType {
	case SSDTokenTypeUser:
		sut, err := GetSsdUserToken(m)
		log.Printf("Valid User Token:%+v:Error=%v", sut, err)
		return sut, nil
	case SSDTokenTypeService:
		sut, err := GetSsdServiceToken(m)
		log.Printf("Valid Service Token:%+v:Error=%v", sut, err)
		return sut, nil
	case SSDTokenTypeInternal:
		sut, err := GetSsdInternalToken(m)
		log.Printf("Valid User Token:%+v:Error=%v", sut, err)
		return sut, nil
	default:
		return nil, fmt.Errorf("unknown token type:%s", tokenType)
	}
}

// Create a signed Token and return the token
func getSignedTokenStr(claims *jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(hmacSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
