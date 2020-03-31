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

type ListRegistrationsInput struct {
	Instance string `json:"-" location:"header" locationKey:"Bluemix-Instance"`
	KeyID    string `json:"-" location:"url" locationKey:"KeyID"`
	CRN      string `json:"-" location:"url" locationKey:"CRN"`
}

type RegistrationDetails struct {
	KeyID              string                 `json:"keyId,omitempty"`
	ResourceCrn        string                 `json:"resourceCrn,omitempty"`
	CreatedBy          string                 `json:"createdBy,omitempty"`
	CreationDate       *time.Time             `json:"creationDate,omitempty"`
	UpdatedBy          string                 `json:"updatedBy,omitempty"`
	LastUpdateDate     *time.Time             `json:"lastUpdated,omitempty"`
	Description        string                 `json:"description,omitempty"`
	PreventKeyDeletion bool                   `json:"preventKeyDeletion"`
	KeyVersion         map[string]interface{} `json:"keyVersion,omitempty"`
}

type RegistrationsMetadata struct {
	CollectionType        string `json:"collectionType"`
	NumberOfRegistrations int    `json:"collectionTotal"`
}

type RegistrationsOutput struct {
	Metadata      RegistrationsMetadata `json:"metadata"`
	Registrations []RegistrationDetails `json:"resources"`
}

type ListRegistrationsRequest struct {
	*Request
	Input *ListRegistrationsInput
}

func (c *Client) ListRegistrationsOfKeyRequest(in *ListRegistrationsInput) ListRegistrationsRequest {
	req := NewRequest(c, "GET", "/api/v2/keys/{{.KeyID}}/registrations", in, &RegistrationsOutput{})

	return ListRegistrationsRequest{Request: req, Input: in}
}

func (c *Client) ListKeysOfRegistrationRequest(in *ListRegistrationsInput) ListRegistrationsRequest {
	req := NewRequest(c, "GET", "/api/v2/keys/registrations?urlEncodedResourceCRNQuery={{.CRN}}", in, &RegistrationsOutput{})

	return ListRegistrationsRequest{Request: req, Input: in}
}

func (r ListRegistrationsRequest) Send(ctx context.Context) (*ListRegistrationsResponse, error) {
	_, err := r.Request.Send(ctx)
	if err != nil {
		return nil, err
	}

	return &ListRegistrationsResponse{
		RegistrationsOutput: r.Request.OutData.(*RegistrationsOutput),
	}, nil
}

type ListRegistrationsResponse struct {
	*RegistrationsOutput
}
