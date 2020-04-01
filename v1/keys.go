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

type GetInput struct {
	Instance string `json:"-" location:"header" locationKey:"Bluemix-Instance"`
	KeyID    string `json:"-" location:"url" locationKey:"KeyID"`
}

type WrapInput struct {
	InstanceID string `json:"-" location:"header" locationKey:"Bluemix-Instance"`
	KeyID      string `json:"-" location:"url" locationKey:"KeyID"`

	Plaintext      *[]byte  `json:"plaintext,omitempty"`
	AdditionalData []string `json:"aad,omitempty"`
}

type WrapOutput struct {
	Plaintext  []byte                 `json:"plaintext, omitempty"`
	Ciphertext []byte                 `json:"ciphertext, omitempty"`
	KeyVersion map[string]interface{} `json:"keyVersion, omitempty"`
}

type WrapRequest struct {
	*Request
	Input *WrapInput
}

func (c *Client) WrapRequest(in *WrapInput) WrapRequest {
	req := NewRequest(c, "POST", "/api/v2/keys/{{.KeyID}}?action=wrap", in, &WrapOutput{})

	return WrapRequest{Request: req, Input: in}
}

func (r WrapRequest) Send(ctx context.Context) (*WrapResponse, error) {
	_, err := r.Request.Send(ctx)
	if err != nil {
		return nil, err
	}
	return &WrapResponse{
		WrapOutput: r.Request.OutData.(*WrapOutput),
	}, nil
}

type WrapResponse struct {
	*WrapOutput
}

type UnwrapInput struct {
	InstanceID string `json:"-" location:"header" locationKey:"Bluemix-Instance"`
	KeyID      string `json:"-" location:"url" locationKey:"KeyID"`

	Ciphertext     []byte   `json:"ciphertext,omitempty"`
	AdditionalData []string `json:"aad,omitempty"`
}

type UnwrapOutput struct {
	Plaintext  []byte                 `json:"plaintext"`
	Ciphertext []byte                 `json:"ciphertext"`
	KeyVersion map[string]interface{} `json:"keyVersion"`
}

type UnwrapRequest struct {
	*Request
	Input *UnwrapInput
}

func (c *Client) UnwrapRequest(in *UnwrapInput) UnwrapRequest {
	req := NewRequest(c, "POST", "/api/v2/keys/{{.KeyID}}?action=unwrap", in, &UnwrapOutput{})

	return UnwrapRequest{Request: req, Input: in}
}

func (r UnwrapRequest) Send(ctx context.Context) (*UnwrapResponse, error) {
	_, err := r.Request.Send(ctx)
	if err != nil {
		return nil, err
	}

	return &UnwrapResponse{
		UnwrapOutput: r.Request.OutData.(*UnwrapOutput),
	}, nil
}

type UnwrapResponse struct {
	*UnwrapOutput
}

type CreatePoliciesInput struct {
	Instance string `json:"-" location:"header" locationKey:"Bluemix-Instance"`
	KeyID    string `json:"-" location:"url" locationKey:"KeyID"`

	Metadata PoliciesMetadata `json:"metadata"`
	Policies *[]PolicyDetails `json:"resources,omitempty" mapstructure:"resources"`
}

type RotationPolicy struct {
	Interval int `json:"interval_month,omitempty"`
}

type DualAuthPolicy struct {
	Enabled bool `json:"enabled,omitempty"`
}

type PolicyDetails struct {
	ID        string          `json:"id,omitempty"`
	Type      string          `json:"type,omitempty"`
	CreatedBy string          `json:"createdBy,omitempty"`
	CreatedAt *time.Time      `json:"creationDate,omitempty"`
	CRN       string          `json:"crn,omitempty"`
	UpdatedAt *time.Time      `json:"lastUpdateDate,omitempty"`
	UpdatedBy string          `json:"updatedBy,omitempty"`
	Rotation  *RotationPolicy `json:"rotation,omitempty" mapstructure:"rotation"`
	DualAuth  *DualAuthPolicy `json:"dualAuthDelete,omitempty" mapstructure:"dualAuthDelete"`
}

// PoliciesMetadata represents the metadata of a collection of keys.
type PoliciesMetadata struct {
	CollectionType   string `json:"collectionType"`
	NumberOfPolicies int    `json:"collectionTotal"`
}

type PoliciesOutput struct {
	Metadata PoliciesMetadata `json:"metadata"`
	Policies *[]PolicyDetails `json:"resources"`
}

type CreatePoliciesRequest struct {
	*Request
	Input *CreatePoliciesInput
}

func (c *Client) CreatePoliciesRequest(in *CreatePoliciesInput) CreatePoliciesRequest {
	req := NewRequest(c, "PUT", "/api/v2/keys/{{.KeyID}}/policies", in, &PoliciesOutput{})

	return CreatePoliciesRequest{Request: req, Input: in}
}

func (r CreatePoliciesRequest) Send(ctx context.Context) (*PoliciesResponse, error) {
	_, err := r.Request.Send(ctx)
	if err != nil {
		return nil, err
	}

	return &PoliciesResponse{
		PoliciesOutput: r.Request.OutData.(*PoliciesOutput),
	}, nil
}

type PoliciesResponse struct {
	*PoliciesOutput
}

type GetPoliciesRequest struct {
	*Request
	Input *GetInput
}

func (c *Client) GetPoliciesRequest(in *GetInput) GetPoliciesRequest {
	req := NewRequest(c, "GET", "/api/v2/keys/{{.KeyID}}/policies", in, &PoliciesOutput{})

	return GetPoliciesRequest{Request: req, Input: in}
}

func (c *Client) GetRotationPolicyRequest(in *GetInput) GetPoliciesRequest {
	req := NewRequest(c, "GET", "/api/v2/keys/{{.KeyID}}/policies?policy=rotation", in, &PoliciesOutput{})

	return GetPoliciesRequest{Request: req, Input: in}
}

func (c *Client) GetDualAuthPolicyRequest(in *GetInput) GetPoliciesRequest {
	req := NewRequest(c, "GET", "/api/v2/keys/{{.KeyID}}/policies?policy=dualAuthDelete", in, &PoliciesOutput{})

	return GetPoliciesRequest{Request: req, Input: in}
}

func (r GetPoliciesRequest) Send(ctx context.Context) (*PoliciesResponse, error) {
	_, err := r.Request.Send(ctx)
	if err != nil {
		return nil, err
	}

	return &PoliciesResponse{
		PoliciesOutput: r.Request.OutData.(*PoliciesOutput),
	}, nil
}
