package kp_test

import (
	"context"
	"fmt"

	kp "github.com/IBM/keyprotect-go-client"
)

func ExampleClient_CreateRootKey() {
	client, _ := kp.New(
		kp.ClientConfig{
			BaseURL:    "https://us-south.kms.cloud.ibm.com",
			APIKey:     "notARealApiKey",
			InstanceID: "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd",
		},
		kp.DefaultTransport(),
	)
	ctx := context.Background()

	rootkey, err := client.CreateRootKey(ctx, "mynewrootkey", nil)
	if err != nil {
		fmt.Println("Error while creating root key: ", err)
	} else {
		fmt.Println("New key created: ", *rootkey)
	}
}

func ExampleClient_WrapCreateDEK() {
	client, _ := kp.New(
		kp.ClientConfig{
			BaseURL:    "https://us-south.kms.cloud.ibm.com",
			APIKey:     "notARealApiKey",
			InstanceID: "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd",
		},
		kp.DefaultTransport(),
	)

	keyId := "1234abcd-abcd-asdf-9eaa-deadbeefabcd"
	aad := []string{
		"AAD can be pretty much any string value.",
		"This entire array of strings is the AAD.",
		"It has to be the same on wrap and unwrap, however",
		"This can be useful, if the DEK should be bound to an application name",
		"or possibly a hostname, IP address, or even email address.",
		"For example",
		"appname=golang-examples;",
		"It is not secret though, so don't put anything sensitive here",
	}

	ctx := context.Background()

	dek, wrappedDek, err := client.WrapCreateDEK(ctx, keyId, &aad)
	if err != nil {
		fmt.Println("Error while creating a DEK: ", err)
	} else {
		fmt.Println("Created new random DEK")
	}

	if len(dek) != 32 {
		fmt.Println("DEK length was not 32 bytes (not a 256 bit key)")
	}

	fmt.Printf("Your WDEK is: %v\n", wrappedDek)

	// dek is your plaintext DEK, use it for encrypt/decrypt and throw it away
	// wrappedDek is your WDEK, keep this and pass it to Unwrap to get back your DEK when you need it again
}

func ExampleClient_UnwrapV2() {
	client, _ := kp.New(
		kp.ClientConfig{
			BaseURL:    "https://us-south.kms.cloud.ibm.com",
			APIKey:     "notARealApiKey",
			InstanceID: "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd",
		},
		kp.DefaultTransport(),
	)

	keyId := "1234abcd-abcd-asdf-9eaa-deadbeefabcd"
	wrappedDek := []byte("dGhpcyBpc24ndCBhIHJlYWwgcGF5bG9hZAo=")
	aad := []string{
		"AAD can be pretty much any string value.",
		"This entire array of strings is the AAD.",
		"It has to be the same on wrap and unwrap, however",
		"This can be useful, if the DEK should be bound to an application name",
		"or possibly a hostname, IP address, or even email address.",
		"For example",
		"appname=golang-examples;",
		"It is not secret though, so don't put anything sensitive here",
	}

	ctx := context.Background()

	dek, rewrapped, err := client.UnwrapV2(ctx, keyId, wrappedDek, &aad)
	if err != nil {
		fmt.Println("Error while unwrapping DEK: ", err)
	} else {
		fmt.Println("Unwrapped key successfully")
	}

	if len(dek) != 32 {
		fmt.Println("DEK length was not 32 bytes (not a 256 bit key)")
	}

	// dek is your plaintext DEK, use it for encrypt/decrypt then throw it away
	// rewrapped is POSSIBLY a new WDEK, if it is not empty, store that and use it on next Unwrap

	if len(rewrapped) > 0 {
		fmt.Printf("Your DEK was rewrapped with a new key version. Your new WDEK is %v\n", rewrapped)

		// store new WDEK
		wrappedDek = rewrapped
	}

}

func ExampleClient_CreateStandardKey() {
	client, _ := kp.New(
		kp.ClientConfig{
			BaseURL:    "https://us-south.kms.cloud.ibm.com",
			APIKey:     "notARealApiKey",
			InstanceID: "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd",
		},
		kp.DefaultTransport(),
	)

	fmt.Println("Creating standard key")
	rootkey, err := client.CreateStandardKey(context.Background(), "mynewstandardkey", nil)
	if err != nil {
		fmt.Println("Error while creating standard key: ", err)
	} else {
		fmt.Println("New key created: ", *rootkey)
	}
}

func ExampleClient_GetKey() {
	client, _ := kp.New(
		kp.ClientConfig{
			BaseURL:    "https://us-south.kms.cloud.ibm.com",
			APIKey:     "notARealApiKey",
			InstanceID: "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd",
		},
		kp.DefaultTransport(),
	)
	keyId := "1234abcd-abcd-asdf-9eaa-deadbeefabcd"

	fmt.Println("Getting standard key")
	key, err := client.GetKey(context.Background(), keyId)
	if err != nil {
		fmt.Println("Get Key failed with error: ", err)
	} else {
		fmt.Printf("Key: %v\n", *key)
	}
}

func ExampleClient_DeleteKey() {
	client, _ := kp.New(
		kp.ClientConfig{
			BaseURL:    "https://us-south.kms.cloud.ibm.com",
			APIKey:     "notARealApiKey",
			InstanceID: "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd",
		},
		kp.DefaultTransport(),
	)
	keyId := "1234abcd-abcd-asdf-9eaa-deadbeefabcd"

	fmt.Println("Deleting standard key")
	delKey, err := client.DeleteKey(context.Background(), keyId, kp.ReturnRepresentation)
	if err != nil {
		fmt.Println("Error while deleting: ", err)
	} else {
		fmt.Println("Deleted key: ", delKey)
	}
}

func ExampleClient_InstancePolicies() {
	client, _ := kp.New(
		kp.ClientConfig{
			BaseURL:    "https://us-south.kms.cloud.ibm.com",
			APIKey:     "notARealApiKey",
			InstanceID: "a6493c3a-5b29-4ac3-9eaa-deadbeef3bfd",
		},
		kp.DefaultTransport(),
	)

	policies := kp.MultiplePolicies{
		DualAuthDelete: &kp.BasicPolicyData{
			Enabled: true,
		},
		AllowedNetwork: &kp.AllowedNetworkPolicyData{
			Enabled: true,
			Network: "public-and-private",
		},
	}

	fmt.Println("Creating instance policies")
	err := client.SetInstancePolicies(context.Background(), policies)
	if err != nil {
		fmt.Println("Error while setting instance policies")
	} else {
		fmt.Println("Set instance polices")
	}

	attributes := map[string]bool{
		"CreateRootKey":     true,
		"CreateStandardKey": true,
	}
	fmt.Println("Setting key create import access instance policy")
	err = client.SetKeyCreateImportAccessInstancePolicy(context.Background(), true, attributes)
	if err != nil {
		fmt.Println("Error while setting key create import access instance policy")
	} else {
		fmt.Println("Set Key Create Import Access instance policy")
	}

}
