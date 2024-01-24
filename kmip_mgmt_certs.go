package kp

import (
	"context"
	"fmt"
	"time"
)

const (
	KMIPClientCertSubPath = "certificates"
	kmipClientCertType    = "application/vnd.ibm.kms.kmip_client_certificate+json"
)

type KMIPClientCertificate struct {
	ID          string     `json:"id,omitempty"`
	Name        string     `json:"name,omitempty"`
	Certificate string     `json:"certificate,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
}

type KMIPClientCertificates struct {
	Metadata     KeysMetadata            `json:"metadata"`
	Certificates []KMIPClientCertificate `json:"resources"`
}

func (c *Client) CreateKMIPClientCertificate(ctx context.Context, adapter_id, cert_payload string, opts ...CreateKMIPClientCertOption) (*KMIPClientCertificate, error) {
	newCert := &KMIPClientCertificate{}
	for _, opt := range opts {
		opt(newCert)
	}
	req, err := c.newRequest("POST", fmt.Sprintf("%s/%s/%s", KMIPAdapterPath, adapter_id, KMIPClientCertSubPath), wrapKMIPClientCert(*newCert))
	if err != nil {
		return nil, err
	}
	certResp := &KMIPClientCertificates{}
	_, err = c.do(ctx, req, certResp)
	if err != nil {
		return nil, err
	}

	return unwrapKMIPClientCert(certResp), nil
}

type CreateKMIPClientCertOption func(*KMIPClientCertificate)

func WithKMIPClientCertName(name string) CreateKMIPClientCertOption {
	return func(cert *KMIPClientCertificate) {
		cert.Name = name
	}
}

func (c *Client) GetKMIPClientCertificates(ctx context.Context, adapter_id string) (*KMIPClientCertificates, error) {
	certs := KMIPClientCertificates{}
	req, err := c.newRequest("GET", fmt.Sprintf("%s/%s/%s", KMIPAdapterPath, adapter_id, KMIPClientCertSubPath), nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, &certs)
	if err != nil {
		return nil, err
	}

	return &certs, nil
}

func (c *Client) GetKMIPClientCertificate(ctx context.Context, adapter_id, cert_id string) (*KMIPClientCertificate, error) {
	certs := &KMIPClientCertificates{}
	req, err := c.newRequest("GET", fmt.Sprintf("%s/%s/%s/%s",
		KMIPAdapterPath, adapter_id, KMIPClientCertSubPath, cert_id), nil)
	if err != nil {
		return nil, err
	}

	_, err = c.do(ctx, req, certs)
	if err != nil {
		return nil, err
	}

	return unwrapKMIPClientCert(certs), nil
}

func (c *Client) DeleteKMIPClientCertificate(ctx context.Context, adapter_id, cert_id string) error {
	req, err := c.newRequest("DELETE", fmt.Sprintf("%s/%s/%s/%s",
		KMIPAdapterPath, adapter_id, KMIPClientCertSubPath, cert_id), nil)
	if err != nil {
		return err
	}

	_, err = c.do(ctx, req, nil)
	if err != nil {
		return err
	}

	return nil
}

func wrapKMIPClientCert(cert KMIPClientCertificate) KMIPClientCertificates {
	return KMIPClientCertificates{
		Metadata: KeysMetadata{
			CollectionType: kmipClientCertType,
			NumberOfKeys:   1,
		},
		Certificates: []KMIPClientCertificate{cert},
	}
}

func unwrapKMIPClientCert(certs *KMIPClientCertificates) *KMIPClientCertificate {
	return &certs.Certificates[0]
}
