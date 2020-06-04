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
func (c *Client) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	policyresponse := Policies{}

	req, err := c.newRequest("GET", fmt.Sprintf("keys/%s/policies", id), nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	return &policyresponse.Policies[0], nil
}

// SetPolicy updates a policy resource by specifying the ID of the key and the rotation interval needed.
func (c *Client) SetPolicy(ctx context.Context, id string, prefer PreferReturn, rotationInterval int) (*Policy, error) {

	policy := Policy{
		Type: policyType,
		Rotation: &Rotation{
			Interval: rotationInterval,
		},
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

	req.Header.Set("Prefer", preferHeaders[prefer])

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	return &policyresponse.Policies[0], nil
}

// GetPolicies retrieves a policy by Key ID.
func (c *Client) GetPolicies(ctx context.Context, id string) ([]Policy, error) {
	policyresponse := Policies{}

	req, err := c.newRequest("GET", fmt.Sprintf("keys/%s/policies", id), nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	return policyresponse.Policies, nil
}

// GetRotationPolivy method retrieves rotation policy details of a key
func (c *Client) GetRotationPolicy(ctx context.Context, id string) (*Policy, error) {
	policyresponse := Policies{}

	req, err := c.newRequest("GET", fmt.Sprintf("keys/%s/policies", id), nil)
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("policy", RotationPolicy)
	req.URL.RawQuery = v.Encode()

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	if len(policyresponse.Policies) == 0 {
		return nil, nil
	}

	return &policyresponse.Policies[0], nil
}

// GetDualAuthDeletePolicy method retrieves dual auth delete policy details of a key
func (c *Client) GetDualAuthDeletePolicy(ctx context.Context, id string) (*Policy, error) {
	policyresponse := Policies{}

	req, err := c.newRequest("GET", fmt.Sprintf("keys/%s/policies", id), nil)
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("policy", DualAuthDelete)
	req.URL.RawQuery = v.Encode()

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	if len(policyresponse.Policies) == 0 {
		return nil, nil
	}

	return &policyresponse.Policies[0], nil
}

// SetRotationPolicy updates the rotation policy associated with a key by specifying key ID and rotation interval
func (c *Client) SetRotationPolicy(ctx context.Context, id string, rotationInterval int) (*Policy, error) {
	policy := Policy{
		Type: policyType,
		Rotation: &Rotation{
			Interval: rotationInterval,
		},
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

	v := url.Values{}
	v.Set("policy", RotationPolicy)
	req.URL.RawQuery = v.Encode()

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	if len(policyresponse.Policies) == 0 {
		return nil, nil
	}

	return &policyresponse.Policies[0], nil
}

// SetDualAuthDeletePolicy updates the dual auth delete policy by passing the key ID and enable detail
func (c *Client) SetDualAuthDeletePolicy(ctx context.Context, id string, enabled bool) (*Policy, error) {
	policy := Policy{
		Type: policyType,
		DualAuth: &DualAuth{
			Enabled: &enabled,
		},
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

	v := url.Values{}
	v.Set("policy", DualAuthDelete)
	req.URL.RawQuery = v.Encode()

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	if len(policyresponse.Policies) == 0 {
		return nil, nil
	}

	return &policyresponse.Policies[0], nil
}

// SetPolicies updates all policies of the key or a single policy by passing key ID.
// To set rotation policy for the key pass the setRotationPolicy parameter as true and set the rotationInterval detail.
// To set dual auth delete policy for the key pass the setDualAuthDeletePolicy parameter as true and set the dualAuthEnable detail.
// Both the policies can be set or either of the policies can be set.
func (c *Client) SetPolicies(ctx context.Context, id string, setRotationPolicy bool, rotationInterval int, setDualAuthDeletePolicy, dualAuthEnable bool) ([]Policy, error) {
	policies := []Policy{}
	if setRotationPolicy {
		rotationPolicy := Policy{
			Type: policyType,
			Rotation: &Rotation{
				Interval: rotationInterval,
			},
		}
		policies = append(policies, rotationPolicy)
	}
	if setDualAuthDeletePolicy {
		dulaAuthPolicy := Policy{
			Type: policyType,
			DualAuth: &DualAuth{
				Enabled: &dualAuthEnable,
			},
		}
		policies = append(policies, dulaAuthPolicy)
	}

	policyRequest := Policies{
		Metadata: PoliciesMetadata{
			CollectionType:   policyType,
			NumberOfPolicies: len(policies),
		},
		Policies: policies,
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

	return policyresponse.Policies, nil
}
