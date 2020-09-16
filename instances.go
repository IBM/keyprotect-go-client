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
	"fmt"
	"net/url"
	"time"
)

const (
	//DualAuthDelete defines the policy type as dual auth delete
	DualAuthDelete = "dualAuthDelete"

	//AllowedNetwork defines the policy type as allowed network
	AllowedNetwork = "allowedNetwork"

	//AllowedIP defines the polity type as allowed ip that are whitelisted
	AllowedIP = "allowedIP"
)

// InstancePolicy represents a instance-level policy of a key as returned by the KP API.
// this policy enables dual authorization for deleting a key
type InstancePolicy struct {
	CreatedBy  string     `json:"createdBy,omitempty"`
	CreatedAt  *time.Time `json:"creationDate,omitempty"`
	UpdatedAt  *time.Time `json:"lastUpdated,omitempty"`
	UpdatedBy  string     `json:"updatedBy,omitempty"`
	PolicyType string     `json:"policy_type,omitempty"`
	PolicyData PolicyData `json:"policy_data,omitempty" mapstructure:"policyData"`
}

// PolicyData contains the details of the policy type
type PolicyData struct {
	Enabled    *bool       `json:"enabled,omitempty"`
	Attributes *Attributes `json:"attributes,omitempty"`
}

// Attributes contains the detals of allowed network policy type
type Attributes struct {
	AllowedNetwork string      `json:"allowed_network,omitempty"`
	AllowedIP      IPAddresses `json:"allowed_ip,omitempty"`
}

// IPAddresses ...
type IPAddresses []string

// InstancePolicies represents a collection of Policies associated with Key Protect instances.
type InstancePolicies struct {
	Metadata PoliciesMetadata `json:"metadata"`
	Policies []InstancePolicy `json:"resources"`
}

// GetDualAuthInstancePolicy retrieves the dual auth delete policy details associated with the instance
// For more information can refer the Key Protect docs in the link below:
// https://cloud.ibm.com/docs/key-protect?topic=key-protect-manage-dual-auth
func (c *Client) GetDualAuthInstancePolicy(ctx context.Context) (*InstancePolicy, error) {
	policyResponse := InstancePolicies{}

	err := c.getInstancePolicy(ctx, DualAuthDelete, &policyResponse)
	if err != nil {
		return nil, err
	}

	if len(policyResponse.Policies) == 0 {
		return nil, nil
	}
	return &policyResponse.Policies[0], nil
}

// GetAllowedNetworkInstancePolicy retrieves the allowed network policy details associated with the instance.
// For more information can refer the Key Protect docs in the link below:
// https://cloud.ibm.com/docs/key-protect?topic=key-protect-managing-network-access-policies
func (c *Client) GetAllowedNetworkInstancePolicy(ctx context.Context) (*InstancePolicy, error) {
	policyResponse := InstancePolicies{}

	err := c.getInstancePolicy(ctx, AllowedNetwork, &policyResponse)
	if err != nil {
		return nil, err
	}

	if len(policyResponse.Policies) == 0 {
		return nil, nil
	}

	return &policyResponse.Policies[0], nil
}

// GetAllowedIPInstancePolicy retrieves the allowed IP instance policy details associated with the instance.
// For more information can refer the Key Protect docs in the link below:
// https://cloud.ibm.com/docs/key-protect?topic=key-protect-manage-allowed-ip
func (c *Client) GetAllowedIPInstancePolicy(ctx context.Context) (*InstancePolicy, error) {
	policyResponse := InstancePolicies{}

	err := c.getInstancePolicy(ctx, AllowedIP, &policyResponse)
	if err != nil {
		return nil, err
	}

	if len(policyResponse.Policies) == 0 {
		return nil, nil
	}

	return &policyResponse.Policies[0], nil
}

func (c *Client) getInstancePolicy(ctx context.Context, policyType string, policyResponse *InstancePolicies) error {
	req, err := c.newRequest("GET", "instance/policies", nil)
	if err != nil {
		return err
	}

	v := url.Values{}
	v.Set("policy", policyType)
	req.URL.RawQuery = v.Encode()

	_, err = c.do(ctx, req, &policyResponse)
	if err != nil {
		return err
	}
	return err
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

func (c *Client) setInstancePolicy(ctx context.Context, policyType string, policyRequest InstancePolicies) error {
	req, err := c.newRequest("PUT", "instance/policies", &policyRequest)
	if err != nil {
		return err
	}

	v := url.Values{}
	v.Set("policy", policyType)
	req.URL.RawQuery = v.Encode()

	policiesResponse := Policies{}
	_, err = c.do(ctx, req, &policiesResponse)
	if err != nil {
		return err
	}
	return err
}

// SetDualAuthInstancePolicy updates the dual auth delete policy details associated with an instance
// For more information can refer the Key Protect docs in the link below:
// https://cloud.ibm.com/docs/key-protect?topic=key-protect-manage-dual-auth
func (c *Client) SetDualAuthInstancePolicy(ctx context.Context, enable bool) error {
	policy := InstancePolicy{
		PolicyType: DualAuthDelete,
		PolicyData: PolicyData{
			Enabled: &enable,
		},
	}

	policyRequest := InstancePolicies{
		Metadata: PoliciesMetadata{
			CollectionType:   policyType,
			NumberOfPolicies: 1,
		},
		Policies: []InstancePolicy{policy},
	}

	err := c.setInstancePolicy(ctx, DualAuthDelete, policyRequest)
	if err != nil {
		return err
	}

	return err
}

// SetAllowedIPInstancePolices updates the allowed IP instance policy details associated with an instance.
// For more information can refet to the Key Protect docs in the link below:
// https://cloud.ibm.com/docs/key-protect?topic=key-protect-manage-allowed-ip
func (c *Client) SetAllowedIPInstancePolicy(ctx context.Context, enable bool, allowedIPs []string) error {
	policy := InstancePolicy{
		PolicyType: AllowedIP,
		PolicyData: PolicyData{
			Enabled: &enable,
		},
	}

	// The IP address validation is performed by the key protect service.
	if enable && len(allowedIPs) != 0 {
		policy.PolicyData.Attributes = &Attributes{}
		policy.PolicyData.Attributes.AllowedIP = allowedIPs
	} else if enable && len(allowedIPs) == 0 {
		return fmt.Errorf("Please provide at least 1 IP subnet specified with CIDR notation")
	} else if !enable && len(allowedIPs) != 0 {
		return fmt.Errorf("IP address list should only be provided if the policy is being enabled")
	}

	policyRequest := InstancePolicies{
		Metadata: PoliciesMetadata{
			CollectionType:   policyType,
			NumberOfPolicies: 1,
		},
		Policies: []InstancePolicy{policy},
	}
	err := c.setInstancePolicy(ctx, AllowedIP, policyRequest)

	return err
}

// SetAllowedNetWorkInstancePolicy updates the allowed network policy details associated with an instance
// For more information can refer to the Key Protect docs in the link below:
// https://cloud.ibm.com/docs/key-protect?topic=key-protect-managing-network-access-policies
func (c *Client) SetAllowedNetworkInstancePolicy(ctx context.Context, enable bool, networkType string) error {
	policy := InstancePolicy{
		PolicyType: AllowedNetwork,
		PolicyData: PolicyData{
			Enabled:    &enable,
			Attributes: &Attributes{},
		},
	}
	if networkType != "" {
		policy.PolicyData.Attributes.AllowedNetwork = networkType
	}

	policyRequest := InstancePolicies{
		Metadata: PoliciesMetadata{
			CollectionType:   policyType,
			NumberOfPolicies: 1,
		},
		Policies: []InstancePolicy{policy},
	}

	err := c.setInstancePolicy(ctx, AllowedNetwork, policyRequest)
	if err != nil {
		return err
	}

	return err
}

// SetInstancePolicies updates single or multiple policy details of an instance.
func (c *Client) SetInstancePolicies(ctx context.Context, setDualAuth, dualAuthEnable bool, setAllowedNetwork, allowedNetworkEnable bool, networkType string) error {
	var policies []InstancePolicy

	if setDualAuth {
		policy := InstancePolicy{
			PolicyType: DualAuthDelete,
		}
		policy.PolicyData.Enabled = &dualAuthEnable
		policies = append(policies, policy)
	}

	if setAllowedNetwork {
		policy := InstancePolicy{
			PolicyType: AllowedNetwork,
			PolicyData: PolicyData{
				Enabled:    &allowedNetworkEnable,
				Attributes: &Attributes{},
			},
		}
		if networkType != "" {
			policy.PolicyData.Attributes.AllowedNetwork = networkType
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

type portsMetadata struct {
	CollectionType string `json:"collectionType"`
	NumberOfPorts  int    `json:"collectionTotal"`
}

type portResponse struct {
	Metadata portsMetadata `json:"metadata"`
	Ports    []privatePort `json:"resources"`
}
type privatePort struct {
	PrivatePort int `json:"private_endpoint_port,omitempty"`
}

// GetAllowedIPPrivateNetworkPort retrieves the private endpoint port assigned to allowed ip policy.
func (c *Client) GetAllowedIPPrivateNetworkPort(ctx context.Context) (int, error) {
	var portResponse portResponse

	req, err := c.newRequest("GET", "instance/allowed_ip_port", nil)
	if err != nil {
		return 0, err
	}

	_, err = c.do(ctx, req, &portResponse)
	if err != nil {
		return 0, err
	}

	if len(portResponse.Ports) == 0 {
		return 0, fmt.Errorf("No port number available. Please check the instance has an enabled allowedIP policy")
	}
	return portResponse.Ports[0].PrivatePort, nil
}
