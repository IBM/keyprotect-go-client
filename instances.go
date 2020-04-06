// Copyright 2019 IBM Corp.
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
	"strings"
	"time"
)

const (
	//DualAuthDelete defines the policy type as dual auth delete
	DualAuthDelete = "dualAuthDelete"

	//AllowedNetwork defines the policy type as allowed network
	AllowedNetwork = "allowedNetwork"
)

// InstancePolicy represents a dual auth delete policy of a key as returned by the KP API.
// this policy enables dual authorization for deleting a key
type InstancePolicy struct {
	CreatedBy  string      `json:"createdBy,omitempty"`
	CreatedAt  *time.Time  `json:"creationDate,omitempty"`
	UpdatedAt  *time.Time  `json:"lastUpdated,omitempty"`
	UpdatedBy  string      `json:"updatedBy,omitempty"`
	PolicyType string      `json:"policy_type,omitempty"`
	PolicyData *PolicyData `json:"policy_data,omitempty" mapstructure:"policyData"`
}

// PolicyData contains the details of the policy type
type PolicyData struct {
	Enabled    *bool       `json:"enabled,omitempty"`
	Attributes *Attributes `json:"attributes,omitempty"`
}

// Attributes contains the detals of allowed network policy type
type Attributes struct {
	AllowedNetwork string `json:"allowed_network,omitempty"`
}

// InstancePolicies represents a collection of Policies associated with Key Protect instances.
type InstancePolicies struct {
	Metadata PoliciesMetadata `json:"metadata"`
	Policies []InstancePolicy `json:"resources"`
}

// GetInstancePolicies retrieves all policies of an Instance.
func (c *Client) GetInstancePolicies(ctx context.Context) ([]InstancePolicy, error) {
	policyresponse := InstancePolicies{}

	req, err := c.newRequest("GET", "instance/policies", nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return nil, err
	}

	return policyresponse.Policies, nil
}

// SetInstancePolicy updates a policy resource of an instance to either allowed network or dual auth or both .
func (c *Client) SetInstancePolicies(ctx context.Context, dualAuthEnabled, allowedNet bool, networkType, setType string) error {
	var policies []InstancePolicy

	if strings.Compare(setType, DualAuthDelete) == 0 {
		policy := InstancePolicy{
			PolicyType: DualAuthDelete,
		}
		policy.PolicyData.Enabled = &dualAuthEnabled
		policies = append(policies, policy)
	}

	if strings.Compare(setType, AllowedNetwork) == 0 {
		policy := InstancePolicy{
			PolicyType: AllowedNetwork,
		}
		policy.PolicyData.Enabled = &allowedNet
		if networkType != "" {
			policy.PolicyData.Attributes = &Attributes{
				AllowedNetwork: networkType,
			}
		}
		policies = append(policies, policy)
	}

	policyRequest := InstancePolicies{
		Metadata: PoliciesMetadata{
			CollectionType:   policyType,
			NumberOfPolicies: len(policies),
		},
		Policies: policies,
	}

	policyresponse := Policies{}

	req, err := c.newRequest("PUT", "instance/policies", &policyRequest)
	if err != nil {
		return err
	}

	_, err = c.do(ctx, req, &policyresponse)
	if err != nil {
		return err
	}

	return nil
}
