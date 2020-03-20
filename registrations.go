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
	"time"
)

type Registration struct {
	KeyID              string     `json:"keyId,omitempty"`
	ResourceCrn        string     `json:"resourceCrn,omitempty"`
	CreatedBy          string     `json:"createdBy,omitempty"`
	CreationDate       time.Time  `json:"creationDate,omitempty"`
	UpdatedBy          string     `json:"updatedBy,omitempty"`
	LastUpdateDate     time.Time  `json:"lastUpdated,omitempty"`
	Description        string     `json:"description,omitempty"`
	PreventKeyDeletion bool       `json:"preventKeyDeletion,omitempty"`
	KeyVersion         KeyVersion `json:"keyVersion,omitempty"`
}

type registrations struct {
	Metadata      KeysMetadata   `json:"metadata"`
	Registrations []Registration `json:"resources"`
}

// ListKeyRegistrations retrieves a collection of registrations of a key of an instance.
// the list provides an understanding of which cloud resources are protected by the key specified
func (c *Client) ListKeyRegistrations(ctx context.Context, keyId string) (*registrations, error) {

	req, err := c.newRequest("GET", fmt.Sprintf("keys/%s/registrations", keyId), nil)
	if err != nil {
		return nil, err
	}

	regs := registrations{}
	_, err = c.do(ctx, req, &regs)
	if err != nil {
		return nil, err
	}

	return &regs, nil
}

// ListAnyKeyRegistrations retrieves a collection of registrations of all keys of an instance.
// the list provides an understanding of which cloud resources are protected by keys
// in the service instance
func (c *Client) ListAnyKeyRegistrations(ctx context.Context) (*registrations, error) {

	req, err := c.newRequest("GET", "keys/registrations", nil)
	if err != nil {
		return nil, err
	}

	regs := registrations{}
	_, err = c.do(ctx, req, &regs)
	if err != nil {
		fmt.Printf("Error here2")
		return nil, err
	}

	return &regs, nil
}
