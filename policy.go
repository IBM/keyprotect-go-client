// Copyright 2020 IBM Corp.
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

package kp

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

const (
	policyType = "application/vnd.ibm.kms.policy+json"

	RotationPolicy = "rotation"
)

// Policy represents a policy as returned by the KP API.
type Policy struct {
	Type      string     `json:"type,omitempty"`
	CreatedBy string     `json:"createdBy,omitempty"`
	CreatedAt *time.Time `json:"creationDate,omitempty"`
	CRN       string     `json:"crn,omitempty"`
	UpdatedAt *time.Time `json:"lastUpdateDate,omitempty"`
	UpdatedBy string     `json:"updatedBy,omitempty"`
	Rotation  *Rotation  `json:"rotation,omitempty"`
	DualAuth  *DualAuth  `json:"dualAuthDelete,omitempty"`
}

type Rotation struct {
	Interval int `json:"interval_month,omitempty"`
}

type DualAuth struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// PoliciesMetadata represents the metadata of a collection of keys.
type PoliciesMetadata struct {
	CollectionType   string `json:"collectionType"`
	NumberOfPolicies int    `json:"collectionTotal"`
}

// Policies represents a collection of Policies.
type Policies struct {
	Metadata PoliciesMetadata `json:"metadata"`
	Policies []Policy         `json:"resources"`
}

// GetPolicy retrieves a policy by Key ID.
func (c *Client) GetPolicy(ctx context.Context, id, policyType string) ([]Policy, error) {
	policyresponse := Policies{}

	req, err := c.newRequest("GET", fmt.Sprintf("keys/%s/policies", id), nil)
	if err != nil {
		return nil, err
	}

	if policyType != "" && (policyType == RotationPolicy || policyType == DualAuthDelete) {
		v := url.Values{}
		v.Set("policy", policyType)
		req.URL.RawQuery = v.Encode()
	}

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	return policyresponse.Policies, nil
}

// SetPolicy updates a policy resource by specifying the ID of the key and the rotation interval needed.
func (c *Client) SetPolicy(ctx context.Context, id, policySetType string, rotationInterval int, dualAuthEnable bool) (*Policy, error) {

	policy := Policy{
		Type: policyType,
	}

	if policySetType == RotationPolicy {
		policy.Rotation = new(Rotation)
		policy.Rotation.Interval = rotationInterval
	} else if policySetType == DualAuthDelete {
		policy.DualAuth = new(DualAuth)
		policy.DualAuth.Enabled = &dualAuthEnable
	}

	policyRequest := Policies{
		Metadata: PoliciesMetadata{
			CollectionType:   policyType,
			NumberOfPolicies: 1,
		},
		Policies: []Policy{policy},
	}

	policyresponse := Policies{}

	req, err := c.newRequest("PUT", fmt.Sprintf("keys/%s/policies", id), &policyRequest)
	if err != nil {
		return nil, err
	}
	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	return &policyresponse.Policies[0], nil
}
