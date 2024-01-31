package kp

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

const (
	KMIPObjectSubPath = "kmip_objects"
	kmipObjectType    = "application/vnd.ibm.kms.kmip_object+json"
)

type KMIPObject struct {
	ID                string     `json:"id,omitempty"`
	KMIPObjectType    int        `json:"kmip_object_type,omitempty"`
	ObjectState       int        `json:"state,omitempty"`
	CreatedByCertID   string     `json:"created_by_kmip_client_cert_id,omitempty"`
	CreatedBy         string     `json:"created_by,omitempty"`
	CreatedAt         *time.Time `json:"created_at,omitempty"`
	UpdatedByCertID   string     `json:"updated_by_kmip_client_cert_id,omitempty"`
	UpdatedBy         string     `json:"updated_by,omitempty"`
	UpdatedAt         *time.Time `json:"updated_at,omitempty"`
	DestroyedByCertID string     `json:"destroyed_by_kmip_client_cert_id,omitempty"`
	DestroyedBy       string     `json:"destroyed_by,omitempty"`
	DestroyedAt       *time.Time `json:"destroyed_at,omitempty"`
}

type KMIPObjects struct {
	Metadata CollectionMetadata `json:"metadata"`
	Objects  []KMIPObject       `json:"resources"`
}

func (c *Client) GetKMIPObjects(ctx context.Context, adapter_id string, limit, offset int, totalCount bool) (*KMIPObjects, error) {
	objects := KMIPObjects{}
	req, err := c.newRequest("GET", fmt.Sprintf("%s/%s/%s", KMIPAdapterPath, adapter_id, KMIPObjectSubPath), nil)
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("limit", strconv.Itoa(limit))
	v.Set("offset", strconv.Itoa(offset))
	if totalCount {
		v.Set("totalCount", "true")
	}
	req.URL.RawQuery = v.Encode()

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
		Metadata: CollectionMetadata{
			CollectionType:  kmipObjectType,
			CollectionTotal: 1,
		},
		Objects: []KMIPObject{object},
	}
}

func unwrapKMIPObject(objects *KMIPObjects) *KMIPObject {
	return &objects.Objects[0]
}
