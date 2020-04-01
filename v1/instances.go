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

package keyprotect

import (
	"context"
	"time"
)

type CreateInstancePoliciesInput struct {
	Instance string `json:"-" location:"header" locationKey:"Bluemix-Instance"`

	Metadata PoliciesMetadata         `json:"metadata"`
	Policies *[]InstancePolicyDetails `json:"resources,omitempty" mapstructure:"resources"`
}

type InstancePolicyDetails struct {
	CreatedBy  string          `json:"createdBy,omitempty"`
	CreatedAt  *time.Time      `json:"creationDate,omitempty"`
	PolicyType string          `json:"policy_type,omitempty"`
	PolicyData *DualAuthPolicy `json:"policy_data,omitempty" mapstructure:"policy_data"`
	UpdatedAt  *time.Time      `json:"lastUpdated,omitempty"`
	UpdatedBy  string          `json:"updatedBy,omitempty"`
}

type CreateInstancePoliciesRequest struct {
	*Request
	Input *CreateInstancePoliciesInput
}

type GetInstancePoliciesRequest struct {
	*Request
	Input *GetInput
}

func (c *Client) CreateInstancePoliciesRequest(in *CreateInstancePoliciesInput) CreateInstancePoliciesRequest {
	req := NewRequest(c, "PUT", "/api/v2/instance/policies", in, &InstancePoliciesOutput{})

	return CreateInstancePoliciesRequest{Request: req, Input: in}
}

func (r CreateInstancePoliciesRequest) Send(ctx context.Context) (int, error) {
	res, err := r.Request.Send(ctx)
	if err != nil {
		return 0, err
	}

	return res.StatusCode, nil
}

func (c *Client) GetInstancePoliciesRequest(in *GetInput) GetInstancePoliciesRequest {
	req := NewRequest(c, "GET", "/api/v2/instance/policies", in, &InstancePoliciesOutput{})

	return GetInstancePoliciesRequest{Request: req, Input: in}
}

func (r GetInstancePoliciesRequest) Send(ctx context.Context) (*InstancePoliciesResponse, error) {
	_, err := r.Request.Send(ctx)
	if err != nil {
		return nil, err
	}

	return &InstancePoliciesResponse{
		InstancePoliciesOutput: r.Request.OutData.(*InstancePoliciesOutput),
	}, nil
}

type InstancePoliciesOutput struct {
	Metadata PoliciesMetadata         `json:"metadata"`
	Policies *[]InstancePolicyDetails `json:"resources"`
}

type InstancePoliciesResponse struct {
	*InstancePoliciesOutput
}
