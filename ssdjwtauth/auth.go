// Copyright 2024 OpsMx, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssdjwtauth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	customClaimName  = "ssd.opsmx.io"
	ssdTokenAudience = "ssd.opsmx.io"
	ssdTokenIssuer   = "OpsMx"

	SSDTokenTypeUser        = "user/v1"
	SSDTokenTypeService     = "service-account/v1"
	SSDTokenTypeInternal    = "internal-account/v1"
	SSDTokenTypeIntegration = "integration/v1"
)

var (
	// signingMethod is used in many places. Chaning it here will cause all usages to automatically
	// adapt, and will invalidate all keys generated with the older method.
	//
	// This uses RSA256 because dgraph doesn't (yet) support PS256.  If/when it does, this should
	// be changed to PS256, which will require changing all tokens, or adding both methods to
	// the verify step so older tokens will continue to work.
	signingMethod jwt.SigningMethod = jwt.SigningMethodRS256
)

type SsdJwtClaims struct {
	jwt.RegisteredClaims
	SSDCLaims SSDClaims `json:"ssd.opsmx.io"`
}

// All possible claims.  For specific types of claims, some subset of these are used,
// and others are ignored.
type SSDClaims struct {
	Type           string   `json:"type,omitempty" yaml:"type,omitempty"`
	Groups         []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	IsAdmin        bool     `json:"isAdmin,omitempty" yaml:"isAdmin,omitempty"`
	Authorizations []string `json:"authorizations,omitempty" yaml:"authorizations,omitempty"`
	OrgID          string   `json:"orgID,omitempty" yaml:"orgID,omitempty"`
	UserID         string   `json:"userID,omitempty" yaml:"userID,omitempty"`
	Service        string   `json:"service,omitempty" yaml:"service,omitempty"`
	Instance       string   `json:"instance,omitempty" yaml:"instance,omitempty"`
	TeamID         string   `json:"teamID,omitempty" yaml:"teamID,omitempty"`
}

type SSDUserClaims struct {
	Type    string   `json:"type,omitempty" yaml:"type,omitempty"`
	Groups  []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	IsAdmin bool     `json:"isAdmin,omitempty" yaml:"isAdmin,omitempty"`
	OrgID   string   `json:"orgID,omitempty" yaml:"orgID,omitempty"`
	UserID  string   `json:"userID,omitempty" yaml:"userID,omitempty"`
}

type SSDServiceClaims struct {
	Type     string `json:"type,omitempty" yaml:"type,omitempty"`
	Service  string `json:"service,omitempty" yaml:"service,omitempty"`
	Instance string `json:"instance,omitempty" yaml:"instance,omitempty"`
	OrgID    string `json:"orgID,omitempty" yaml:"orgID,omitempty"`
}

type SSDInternalClaims struct {
	Type           string   `json:"type,omitempty" yaml:"type,omitempty"`
	Service        string   `json:"service,omitempty" yaml:"service,omitempty"`
	Authorizations []string `json:"authorizations,omitempty" yaml:"authorizations,omitempty"`
}

type SSDIntegrationClaims struct {
	Type   string `json:"type,omitempty" yaml:"type,omitempty"`
	TeamID string `json:"teamID,omitempty" yaml:"teamID,omitempty"`
	OrgID  string `json:"orgID,omitempty" yaml:"orgID,omitempty"`
}

func SSDUserClaimsFromClaims(s *SsdJwtClaims) (*SSDUserClaims, error) {
	if s.SSDCLaims.Type != SSDTokenTypeUser {
		return nil, fmt.Errorf("cannot parse user claims from type %s", s.SSDCLaims.Type)
	}
	if s.SSDCLaims.UserID == "" {
		return nil, fmt.Errorf("required field userID is not set in claims")
	}
	if s.SSDCLaims.OrgID == "" {
		return nil, fmt.Errorf("required field orgID is not set in claims")
	}
	groups := s.SSDCLaims.Groups
	if len(groups) == 0 {
		groups = []string{}
	}
	ret := SSDUserClaims{
		Type:    s.SSDCLaims.Type,
		UserID:  s.SSDCLaims.UserID,
		OrgID:   s.SSDCLaims.OrgID,
		IsAdmin: s.SSDCLaims.IsAdmin,
		Groups:  groups,
	}
	return &ret, nil
}

// TODO: check that the fields are valid
func SSDUserClaimsToClaims(c *SSDUserClaims) (SSDClaims, error) {
	return SSDClaims{
		Type:    SSDTokenTypeUser,
		OrgID:   c.OrgID,
		IsAdmin: c.IsAdmin,
		Groups:  c.Groups,
		UserID:  c.UserID,
	}, nil
}

func SSDServiceClaimsFromClaims(s *SsdJwtClaims) (*SSDServiceClaims, error) {
	if s.SSDCLaims.Type != SSDTokenTypeService {
		return nil, fmt.Errorf("cannot parse service claims from type %s", s.SSDCLaims.Type)
	}
	if s.SSDCLaims.Service == "" {
		return nil, fmt.Errorf("required field service is not set in claims")
	}
	if s.SSDCLaims.Instance == "" {
		return nil, fmt.Errorf("required field instance is not set in claims")
	}
	if s.SSDCLaims.OrgID == "" {
		return nil, fmt.Errorf("required field orgID is not set in claims")
	}
	ret := SSDServiceClaims{
		Type:     s.SSDCLaims.Type,
		Service:  s.SSDCLaims.Service,
		Instance: s.SSDCLaims.Instance,
		OrgID:    s.SSDCLaims.OrgID,
	}
	return &ret, nil
}

// TODO: check that the fields are valid
func SSDServiceClaimsToClaims(c *SSDServiceClaims) (SSDClaims, error) {
	return SSDClaims{
		Type:     SSDTokenTypeService,
		Service:  c.Service,
		OrgID:    c.OrgID,
		Instance: c.Instance,
	}, nil
}

func SSDInternalClaimsFromClaims(s *SsdJwtClaims) (*SSDInternalClaims, error) {
	if s.SSDCLaims.Type != "internal-account/v1" {
		return nil, fmt.Errorf("cannot parse internal claims from type %s", s.SSDCLaims.Type)
	}
	authorizations := s.SSDCLaims.Authorizations
	if len(authorizations) == 0 {
		authorizations = []string{}
	}
	ret := SSDInternalClaims{
		Type:           s.SSDCLaims.Type,
		Service:        s.SSDCLaims.Service,
		Authorizations: authorizations,
	}
	return &ret, nil
}

// TODO: check that the fields are valid
func SSDInternalClaimsToClaims(c *SSDInternalClaims) (SSDClaims, error) {
	return SSDClaims{
		Type:           SSDTokenTypeInternal,
		Service:        c.Service,
		Authorizations: c.Authorizations,
	}, nil
}

func SSDIntegrationClaimsFromClaims(s *SsdJwtClaims) (*SSDIntegrationClaims, error) {
	if s.SSDCLaims.Type != SSDTokenTypeIntegration {
		return nil, fmt.Errorf("cannot parse integration claims from type %s", s.SSDCLaims.Type)
	}
	if s.SSDCLaims.TeamID == "" {
		return nil, fmt.Errorf("required field teamID is not set in claims")
	}
	if s.SSDCLaims.OrgID == "" {
		return nil, fmt.Errorf("required field orgID is not set in claims")
	}

	ret := SSDIntegrationClaims{
		Type:   s.SSDCLaims.Type,
		TeamID: s.SSDCLaims.TeamID,
		OrgID:  s.SSDCLaims.OrgID,
	}
	return &ret, nil
}

func SSDIntegrationClaimsToClaims(c *SSDIntegrationClaims) (SSDClaims, error) {
	return SSDClaims{
		Type:   SSDTokenTypeIntegration,
		OrgID:  c.OrgID,
		TeamID: c.TeamID,
	}, nil
}
