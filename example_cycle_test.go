package kp_test

import (
	"context"
	"fmt"
	"os"

	kp "github.com/IBM/keyprotect-go-client"
)

func NewClient() (*kp.Client, error) {
	instanceId, ok := os.LookupEnv("KP_INSTANCE_ID")
	if !ok {
		panic("Must set KP_INSTANCE_ID")
	}

	apiKey, ok := os.LookupEnv("IBMCLOUD_API_KEY")
	if !ok {
		panic("Must set IBMCLOUD_API_KEY")
	}
	if apiKey == "" {
		panic("IBMCLOUD_API_KEY was empty")
	}

	cc := kp.ClientConfig{
		BaseURL:    "https://us-south.kms.cloud.ibm.com",
		APIKey:     apiKey,
		InstanceID: instanceId,
	}

	return kp.New(cc, kp.DefaultTransport())
}

func Example() {
	c, _ := NewClient()

	ctx := context.Background()

	// List keys in the current instance
	keys, err := c.GetKeys(ctx, 0, 0)
	if err != nil {
		panic(err)
	}
	for _, key := range keys.Keys {
		fmt.Printf("%+v\n", key)
	}

	// Create a new non-exportable key
	crk, err := c.CreateKey(ctx, "kp-go-example-crk", false)
	if err != nil {
		panic(err)
	}
	fmt.Printf("CRK created successfully: id=%s\n", crk.ID)

	// Create a new DEK and WDEK pair, using the root key from above.
	// The DEK is a piece of secret information that is used for encrypt/decrypt.
	// The WDEK (or wrapped DEK) is used to retrieve the DEK when you need it again.
	ptDek, wdek, err := c.WrapCreateDEK(ctx, crk.ID, nil)
	if err != nil {
		panic(err)
	}

	// Unwrap our WDEK, getting back the corresponding DEK
	unwrapped, _, err := c.UnwrapV2(ctx, crk.ID, wdek, nil)

	if string(unwrapped) != string(ptDek) {
		panic("Unwrapped DEK did not match DEK from Wrap!")
	}

	// Delete the root key in KeyProtect.
	// Any WDEKs created with the root key will no longer be able to be unwrapped.
	// If you didn't store your DEKs elsewhere, all the data encrypted by those DEKs
	// is now crypto-erased.
	//
	// For some this is a feature. For others it might be a nightmare.
	// Make very sure that the key should be deleted.
	_, err = c.DeleteKey(ctx, crk.ID, 0)
	if err != nil {
		panic(fmt.Sprintf("Error deleting key: %s\n", err))
	}
	fmt.Printf("Key deleted: id=%s\n", crk.ID)
}
