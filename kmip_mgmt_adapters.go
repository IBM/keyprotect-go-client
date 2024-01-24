package kp

import (
	"context"
	"fmt"
	"time"
)

const (
	KMIPAdapterPath = "kmip_adapters"
	kmipAdapterType = "application/vnd.ibm.kms.kmip_adapter+json"
)

type KMIPAdapter struct {
	ID          string      `json:"id,omitempty"`
	Profile     string      `json:"profile,omitempty"`
	ProfileData kmipProfile `json:"profile_data,omitempty"`
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description"`
	CreatedBy   string      `json:"created_by,omitempty"`
	CreatedAt   *time.Time  `json:"created_at,omitempty"`
	UpdatedBy   string      `json:"updated_by,omitempty"`
	UpdatedAt   *time.Time  `json:"updated_at,omitempty"`
}

type KMIPAdapters struct {
	Metadata KeysMetadata  `json:"metadata"`
	Adapters []KMIPAdapter `json:"resources"`
}

type kmipProfile interface {
	Type() string
}

type KMIPProfileNative struct {
	CrkID string `json:"crk_id"`
}

func (k KMIPProfileNative) Type() string { return KMIP_Profile_Native }

const (
	KMIP_Profile_Native = "native_1.0"
)

// CreateKMIPAdapter method creates a KMIP Adapter with the specified profile.
// For information please refer to the link below:
// https://cloud.ibm.com/docs/key-protect?topic=placeholder
func (c *Client) CreateKMIPAdapter(ctx context.Context, profile CreateKMIPAdapterProfile, options ...CreateKMIPAdapterOption) (*KMIPAdapter, error) {
	newAdapter := &KMIPAdapter{}
	profile(newAdapter)
	for _, opt := range options {
		opt(newAdapter)
	}
	req, err := c.newRequest("POST", KMIPAdapterPath, wrapKMIPAdapter(*newAdapter))
	if err != nil {
		return nil, err
	}

	create_resp := &KMIPAdapters{}
	_, err = c.do(ctx, req, create_resp)
	if err != nil {
		return nil, err
	}

	return unwrapKMIPAdapterResp(create_resp), nil
}

type CreateKMIPAdapterOption func(*KMIPAdapter)
type CreateKMIPAdapterProfile func(*KMIPAdapter)

func WithKMIPAdapterName(name string) CreateKMIPAdapterOption {
	return func(adapter *KMIPAdapter) {
		adapter.Name = name
	}
}

func WithKMIPAdapterDescription(description string) CreateKMIPAdapterOption {
	return func(adapter *KMIPAdapter) {
		adapter.Description = description
	}
}

func WithNativeProfile(crkID string) CreateKMIPAdapterProfile {
	return func(adapter *KMIPAdapter) {
		adapter.Profile = KMIP_Profile_Native

		adapter.ProfileData = KMIPProfileNative{
			CrkID: crkID,
		}
	}
}

func (c *Client) GetKMIPAdapters(ctx context.Context) (*KMIPAdapters, error) {
	adapters := KMIPAdapters{}
	req, err := c.newRequest("GET", KMIPAdapterPath, nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, &adapters)
	if err != nil {
		return nil, err
	}

	return &adapters, nil
}

func (c *Client) GetKMIPAdapter(ctx context.Context, id string) (*KMIPAdapter, error) {
	adapters := KMIPAdapters{}
	req, err := c.newRequest("GET", fmt.Sprintf("%s/%s", KMIPAdapterPath, id), nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, &adapters)
	if err != nil {
		return nil, err
	}

	return &adapters.Adapters[0], nil
}

func (c *Client) DeleteKMIPAdapter(ctx context.Context, id string) error {
	req, err := c.newRequest("DELETE", fmt.Sprintf("%s/%s", KMIPAdapterPath, id), nil)

	if err != nil {
		return err
	}

	_, err = c.do(ctx, req, nil)
	if err != nil {
		return err
	}

	return nil
}

func wrapKMIPAdapter(adapter KMIPAdapter) KMIPAdapters {
	return KMIPAdapters{
		Metadata: KeysMetadata{
			CollectionType: kmipAdapterType,
			NumberOfKeys:   1,
		},
		Adapters: []KMIPAdapter{adapter},
	}
}

func unwrapKMIPAdapterResp(resp *KMIPAdapters) *KMIPAdapter {
	return &resp.Adapters[0]
}
