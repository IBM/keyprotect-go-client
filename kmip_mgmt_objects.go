package kp

import (
	"context"
	"fmt"
)

const (
	KMIPObjectSubPath = "kmip_objects"
	kmipObjectType    = "application/vnd.ibm.kms.kmip_object+json"
)

type KMIPObject struct {
	ID                string
	KMIPObjectType    int
	KMIPAdapterID     string
	CreatedByCertID   string
	CreatedBy         string
	CreatedAt         string
	UpdatedByCertID   string
	UpdatedBy         string
	UpdatedAt         string
	DestroyedByCertID string
	DestroyedBy       string
	DestroyedAt       string
}

type KMIPObjects struct {
	Metadata KeysMetadata `json:"metadata"`
	Objects  []KMIPObject `json:"resources"`
}

func (c *Client) GetKMIPObject(ctx context.Context, adapter_id string) (*KMIPObject, error) {
	objects := KMIPObject{}
	req, err := c.newRequest("GET", fmt.Sprintf("%s/%s/%s", KMIPAdapterPath, adapter_id, KMIPObjectSubPath), nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, &objects)
	if err != nil {
		return nil, err
	}

	return &objects, nil
}

func (c *Client) GetKMIPObject(ctx context.Context, adapter_id, object_id string) (*KMIPObject, error) {
	objects := &KMIPObjects{}
	req, err := c.newRequest("GET", fmt.Sprintf("%s/%s/%s/%s",
		KMIPAdapterPath, adapter_id, KMIPObjectSubPath, object_id), nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, objects)
	if err != nil {
		return nil, err
	}

	return unwrapKMIPObject(objects), nil
}

func (c *Client) DeleteKMIPObject(ctx context.Context, adapter_id, object_id string) error {
	req, err := c.newRequest("DELETE", fmt.Sprintf("%s/%s/%s/%s",
		KMIPAdapterPath, adapter_id, KMIPObjectSubPath, object_id), nil)
	if err != nil {
		return err
	}

	_, err = c.do(ctx, req, nil)
	if err != nil {
		return err
	}

	return nil
}

func wrapKMIPObject(object KMIPObject) KMIPObjects {
	return KMIPObjects{
		Metadata: KeysMetadata{
			CollectionType: kmipObjectType,
			NumberOfKeys:   1,
		},
		Objects: []KMIPObject{object},
	}
}

func unwrapKMIPObject(objects *KMIPObjects) *KMIPObject {
	return &objects.Objects[0]
}

//TODO: get list delete
