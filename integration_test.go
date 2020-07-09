// +build integration

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

// These are tests that run across the network against a real KeyProtect service.
// The goal of this is to provide a more extended test other than regular unit
// tests that can be used by a developer locally to check interactions between
// the client code (Code Under Test) against a current and live API of KeyProtect.
// We are not testing the KeyProtect APIs, and we should not try to. That task
// should be handled by a proper API regression test suite for the service itself.

// To use this, you will need to set KP_INSTANCE_ID and IBMCLOUD_API_KEY environment variables.
// KP_INSTANCE_ID should be set to the UUID of a pre-created instance of the KeyProtect service in the US-SOUTH region.
// IBMCLOUD_API_KEY should be an IAM API Key that has access to the instance that KP_INSTANCE_ID refers to.

import (
	"context"
	"os"

	"github.com/stretchr/testify/assert"
	"testing"
)

func NewIntegrationTestClient(t *testing.T) (*API, error) {
	instanceId, ok := os.LookupEnv("KP_INSTANCE_ID")
	if !ok {
		t.Fatal("Must set KP_INSTANCE_ID")
	}

	apiKey, ok := os.LookupEnv("IBMCLOUD_API_KEY")
	if !ok {
		t.Fatal("Must set IBMCLOUD_API_KEY")
	}
	if apiKey == "" {
		t.Fatal("IBMCLOUD_API_KEY was empty")
	}

	cc := ClientConfig{
		BaseURL:    DefaultBaseURL,
		APIKey:     apiKey,
		InstanceID: instanceId,
		TokenURL:   DefaultTokenURL,
		Verbose:    VerboseAll,
		Timeout:    10.0,
	}

	return New(cc, DefaultTransport())
}

// TestWrapUnwrap calls Wrap to create a new DEK, then
// attempts to Unwrap the ciphertext and compares it with the
// plaintext DEK it got from Wrap.
// This is basically what 98% of the calls to KeyProtect are.
func TestWrapUnwrap(t *testing.T) {
	assert := assert.New(t)

	c, err := NewIntegrationTestClient(t)
	assert.NoError(err)

	ctx := context.Background()

	keys, err := c.GetKeys(ctx, 0, 0)
	assert.NoError(err)

	for _, key := range keys.Keys {
		t.Logf("%+v\n", key)
	}

	crk, err := c.CreateKey(ctx, "kptest-crk", nil, false)
	assert.NoError(err)
	t.Logf("CRK created successfully: id=%s\n", crk.ID)

	metadata, err := c.GetKeyMetadata(ctx, crk.ID)
	assert.NoError(err)
	assert.False(t, metadata.Deleted)
	assert.Empty(t, metadata.Payload)

	ptDek, wdek, err := c.WrapCreateDEK(ctx, crk.ID, nil)
	assert.NoError(err)

	unwrapped, err := c.Unwrap(ctx, crk.ID, wdek, nil)
	assert.EqualValues(unwrapped, ptDek)

	keys, err = c.GetKeys(context.Background(), 0, 0)
	assert.NoError(err)

	for _, key := range keys.Keys {
		if key.Name == "kptest-crk" {
			_, err := c.DeleteKey(ctx, key.ID, 0)
			if err != nil {
				t.Logf("Error deleting key: %s\n", err)
			} else {
				t.Logf("Key deleted: id=%s\n", key.ID)
			}
		}
	}
}

func TestRotatedKeyHasLastUpdatedAndRotated(t *testing.T) {
	assert := assert.New(t)

	c, err := NewIntegrationTestClient(t)
	assert.NoError(err)

	ctx := context.Background()

	keys, err := c.GetKeys(ctx, 0, 0)
	assert.NoError(err)

	for _, key := range keys.Keys {
		t.Logf("%+v\n", key)
	}

	crk, err := c.CreateKey(ctx, "kptest-crk", nil, false)
	assert.NoError(err)
	t.Logf("CRK created successfully: id=%s\n", crk.ID)

	assert.Nil(crk.LastUpdateDate)
	assert.Nil(crk.LastRotateDate)

	err = c.Rotate(ctx, crk.ID, "")
	assert.NoError(err)
	t.Logf("CRK rotated successfully: id=%s\n", crk.ID)

	rotated, err := c.GetKey(ctx, crk.ID)

	assert.NotEmpty(rotated.LastUpdateDate)
	assert.NotEmpty(rotated.LastRotateDate)

	keys, err = c.GetKeys(context.Background(), 0, 0)
	assert.NoError(err)

	for _, key := range keys.Keys {
		if key.Name == "kptest-crk" {
			_, err := c.DeleteKey(ctx, key.ID, 0)
			if err != nil {
				t.Logf("Error deleting key: %s\n", err)
			} else {
				t.Logf("Key deleted: id=%s\n", key.ID)
			}
		}
	}
}
