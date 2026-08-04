//go:build examples

/**
 * (C) Copyright IBM Corp. 2026.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ibmkeyprotectapiv2_test

// MANUAL: Added "encoding/json", "io", "strings", and "time" imports to support
// constructing real JSON request bodies, io.NopCloser wrappers, and rate-limit waits.
// The generated file only imported "fmt" and "os".
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// MANUAL: generateTestCertPEM produces a self-signed X.509 certificate in memory,
// removing the need for a pre-generated temp.pem file or an external openssl
// invocation.
func generateTestCertPEM() string {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	Expect(err).To(BeNil())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"XX"},
			Province:           []string{"TX"},
			Locality:           []string{"Austin"},
			Organization:       []string{"IBM"},
			OrganizationalUnit: []string{"KP"},
			CommonName:         "CommonNameOrHostname",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).To(BeNil())

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

// This file provides an example of how to use the IBM Key Protect API service.
//
// The following configuration properties are assumed to be defined:
// IBM_KEY_PROTECT_API_URL=<service base url>
// IBM_KEY_PROTECT_API_AUTH_TYPE=iam
// IBM_KEY_PROTECT_API_APIKEY=<IAM apikey>
// IBM_KEY_PROTECT_API_AUTH_URL=<IAM token service base URL - omit this if using the production environment>
// IBM_KEY_PROTECT_API_BLUEMIX_INSTANCE=<instance UUID>  // MANUAL: Added — required by every API call
//
// These configuration properties can be exported as environment variables, or stored
// in a configuration file and then:
// export IBM_CREDENTIALS_FILE=<name of configuration file>
var _ = Describe(`IbmKeyProtectApiV2 Examples Tests`, func() {

	// MANUAL: Path changed from "../ibm_key_protect_api_v2.env" to "./ibm_key_protect_api_v2.env"
	// to match the location of the env file when tests are run from the ibmkeyprotectapiv2/ directory.
	const externalConfigFile = "./ibm_key_protect_api_v2.env"

	var (
		ibmKeyProtectApiService *ibmkeyprotectapiv2.IbmKeyProtectApiV2
		config                  map[string]string

		// MANUAL: Added package-level shared state variables so that resources created in early
		// examples (keys, key rings, KMIP adapters) can be referenced by later examples without
		// hardcoding IDs. The generated file had no shared state — every call used "testString".
		exampleBluemixInstance string
		exampleKeyID           string                  // populated by CreateKey; used by all single-key examples
		exampleKeyID2          string                  // populated by CreateKeyWithPoliciesOverrides; used by policy/KMIP examples
		exampleCiphertext      string                  // populated by WrapKey; used by UnwrapKey and RewrapKey
		exampleKeyringID       = "example-keyring"     // constant name for the example key ring
		exampleKmipName        = "example-kmip"        // constant name for the example KMIP adapter
		exampleKmipCertName    = "Example-certificate" // constant name for the example KMIP client certificate
		exampleDisableTS       time.Time               // set by DisableKey; used by EnableKey to enforce the 31-second rate limit
		exampleDeleteTS        time.Time               // set by DeleteKey; used by RestoreKey to enforce the 31-second rate limit
	)

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping examples...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			var err error
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping examples: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(ibmkeyprotectapiv2.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping examples: " + err.Error())
			} else if len(config) == 0 {
				Skip("Unable to load service properties, skipping examples")
			}

			// MANUAL: Load BLUEMIX_INSTANCE from config and store in the shared state variable.
			// The generated code had no concept of a shared instance ID; every call hardcoded "testString".
			exampleBluemixInstance = config["BLUEMIX_INSTANCE"]
			if exampleBluemixInstance == "" {
				Skip("Unable to load BLUEMIX_INSTANCE configuration property, skipping examples")
			}

			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {
			var err error

			// begin-common

			ibmKeyProtectApiServiceOptions := &ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{}

			ibmKeyProtectApiService, err = ibmkeyprotectapiv2.NewIbmKeyProtectApiV2UsingExternalConfig(ibmKeyProtectApiServiceOptions)

			if err != nil {
				panic(err)
			}

			// end-common

			Expect(ibmKeyProtectApiService).ToNot(BeNil())
		})
	})

	Describe(`IbmKeyProtectApiV2 request examples`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKeyCollectionMetadata request example`, func() {
			// begin-getKeyCollectionMetadata

			getKeyCollectionMetadataOptions := ibmKeyProtectApiService.NewGetKeyCollectionMetadataOptions(
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.GetKeyCollectionMetadata(getKeyCollectionMetadataOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 200 {
				fmt.Printf("\nUnexpected response status code received from GetKeyCollectionMetadata(): %d\n", response.StatusCode)
			}

			// end-getKeyCollectionMetadata

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
		})
		It(`CreateKey request example`, func() {
			fmt.Println("\nCreateKey() result:")
			// begin-createKey

			// MANUAL: Replaced CreateMockReader("This is a mock file.") with a real JSON body.
			// The generated code sent an invalid body which the API would reject.
			keyCreateBody := map[string]interface{}{
				"metadata": map[string]interface{}{
					"collectionType":  "application/vnd.ibm.kms.key+json",
					"collectionTotal": 1,
				},
				"resources": []map[string]interface{}{
					{
						"type":        "application/vnd.ibm.kms.key+json",
						"name":        "example-root-key",
						"description": "An example IBM Key Protect root key",
						"extractable": false,
					},
				},
			}
			keyCreateBodyJSON, _ := json.Marshal(keyCreateBody)

			// MANUAL: io.NopCloser wraps *strings.Reader to satisfy the io.ReadCloser interface
			// required by the SDK; strings.NewReader alone does not implement Close().
			createKeyOptions := ibmKeyProtectApiService.NewCreateKeyOptions(
				exampleBluemixInstance,
				io.NopCloser(strings.NewReader(string(keyCreateBodyJSON))),
			)
			createKeyOptions.SetPrefer("return=representation")

			key, response, err := ibmKeyProtectApiService.CreateKey(createKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(key, "", "  ")
			fmt.Println(string(b))

			// end-createKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(key).ToNot(BeNil())
			Expect(len(key.Resources)).To(BeNumerically(">", 0))
			exampleKeyID = *key.Resources[0].ID // MANUAL: Capture the created key ID for use in subsequent examples.
		})
		It(`GetKeys request example`, func() {
			fmt.Println("\nGetKeys() result:")
			// begin-getKeys

			getKeysOptions := ibmKeyProtectApiService.NewGetKeysOptions(
				exampleBluemixInstance,
			)

			listKeys, response, err := ibmKeyProtectApiService.GetKeys(getKeysOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKeys, "", "  ")
			fmt.Println(string(b))

			// end-getKeys

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKeys).ToNot(BeNil())
		})
		It(`CreateKeyWithPoliciesOverrides request example`, func() {
			fmt.Println("\nCreateKeyWithPoliciesOverrides() result:")
			// begin-createKeyWithPoliciesOverrides

			// MANUAL: Replaced CreateMockReader with a real JSON body including policy override fields
			// (dualAuthDelete disabled, rotation enabled at 6-month interval).
			keyWithPolicyOverridesCreateBody := map[string]interface{}{
				"metadata": map[string]interface{}{
					"collectionType":  "application/vnd.ibm.kms.key+json",
					"collectionTotal": 1,
				},
				"resources": []map[string]interface{}{
					{
						"type":        "application/vnd.ibm.kms.key+json",
						"name":        "example-policies-overridden-key",
						"description": "An example IBM Key Protect key with policy overrides",
						"extractable": false,
						"dualAuthDelete": map[string]interface{}{
							"enabled": false,
						},
						"rotation": map[string]interface{}{
							"enabled":        true,
							"interval_month": 6,
						},
					},
				},
			}
			keyWithPolicyOverridesCreateBodyJSON, _ := json.Marshal(keyWithPolicyOverridesCreateBody)

			createKeyWithPoliciesOverridesOptions := ibmKeyProtectApiService.NewCreateKeyWithPoliciesOverridesOptions(
				exampleBluemixInstance,
				io.NopCloser(strings.NewReader(string(keyWithPolicyOverridesCreateBodyJSON))),
			)
			createKeyWithPoliciesOverridesOptions.SetPrefer("return=representation")

			key, response, err := ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(key, "", "  ")
			fmt.Println(string(b))

			// end-createKeyWithPoliciesOverrides

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(key).ToNot(BeNil())
			Expect(len(key.Resources)).To(BeNumerically(">", 0))
			exampleKeyID2 = *key.Resources[0].ID // MANUAL: Capture the policies-overridden key ID.
		})
		It(`GetKey request example`, func() {
			fmt.Println("\nGetKey() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-getKey

			getKeyOptions := ibmKeyProtectApiService.NewGetKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)

			getKey, response, err := ibmKeyProtectApiService.GetKey(getKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(getKey, "", "  ")
			fmt.Println(string(b))

			// end-getKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKey).ToNot(BeNil())
		})
		It(`GetKeyMetadata request example`, func() {
			fmt.Println("\nGetKeyMetadata() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-getKeyMetadata

			getKeyMetadataOptions := ibmKeyProtectApiService.NewGetKeyMetadataOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)

			getKeyMetadata, response, err := ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(getKeyMetadata, "", "  ")
			fmt.Println(string(b))

			// end-getKeyMetadata

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKeyMetadata).ToNot(BeNil())
		})
		It(`GetKeyVersions request example`, func() {
			fmt.Println("\nGetKeyVersions() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-getKeyVersions

			getKeyVersionsOptions := ibmKeyProtectApiService.NewGetKeyVersionsOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)

			listKeyVersions, response, err := ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKeyVersions, "", "  ")
			fmt.Println(string(b))

			// end-getKeyVersions

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKeyVersions).ToNot(BeNil())
		})
		It(`WrapKey request example`, func() {
			fmt.Println("\nWrapKey() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-wrapKey

			// MANUAL: Replaced empty options with a real JSON body containing a base64 plaintext.
			keyActionWrapBody := map[string]interface{}{
				"plaintext": "cGxhaW50ZXh0LWRhdGEta2V5",
			}
			keyActionWrapBodyJSON, _ := json.Marshal(keyActionWrapBody)

			wrapKeyOptions := ibmKeyProtectApiService.NewWrapKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)
			wrapKeyOptions.SetKeyActionWrapBody(io.NopCloser(strings.NewReader(string(keyActionWrapBodyJSON))))

			wrapKeyResponseBody, response, err := ibmKeyProtectApiService.WrapKey(wrapKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(wrapKeyResponseBody, "", "  ")
			fmt.Println(string(b))

			// end-wrapKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(wrapKeyResponseBody).ToNot(BeNil())
			Expect(wrapKeyResponseBody.Ciphertext).ToNot(BeNil())
			exampleCiphertext = *wrapKeyResponseBody.Ciphertext // MANUAL: Store ciphertext for UnwrapKey/RewrapKey.
		})
		It(`UnwrapKey request example`, func() {
			fmt.Println("\nUnwrapKey() result:")
			// MANUAL: Skip guards added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			if exampleCiphertext == "" {
				Skip("No ciphertext available from WrapKey, skipping")
			}
			// begin-unwrapKey

			// MANUAL: Replaced CreateMockReader with a real JSON body using the stored ciphertext.
			keyActionUnwrapBody := map[string]interface{}{
				"ciphertext": exampleCiphertext,
			}
			keyActionUnwrapBodyJSON, _ := json.Marshal(keyActionUnwrapBody)

			unwrapKeyOptions := ibmKeyProtectApiService.NewUnwrapKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
				io.NopCloser(strings.NewReader(string(keyActionUnwrapBodyJSON))),
			)

			unwrapKeyResponseBody, response, err := ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(unwrapKeyResponseBody, "", "  ")
			fmt.Println(string(b))

			// end-unwrapKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(unwrapKeyResponseBody).ToNot(BeNil())
		})
		It(`RewrapKey request example`, func() {
			fmt.Println("\nRewrapKey() result:")
			// MANUAL: Skip guards added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			if exampleCiphertext == "" {
				Skip("No ciphertext available from WrapKey, skipping")
			}
			// begin-rewrapKey

			// MANUAL: Replaced CreateMockReader with a real JSON body using the stored ciphertext.
			keyActionRewrapBody := map[string]interface{}{
				"ciphertext": exampleCiphertext,
			}
			keyActionRewrapBodyJSON, _ := json.Marshal(keyActionRewrapBody)

			rewrapKeyOptions := ibmKeyProtectApiService.NewRewrapKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
				io.NopCloser(strings.NewReader(string(keyActionRewrapBodyJSON))),
			)

			rewrapKeyResponseBody, response, err := ibmKeyProtectApiService.RewrapKey(rewrapKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(rewrapKeyResponseBody, "", "  ")
			fmt.Println(string(b))

			// end-rewrapKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(rewrapKeyResponseBody).ToNot(BeNil())
		})
		It(`RotateKey request example`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-rotateKey

			rotateKeyOptions := ibmKeyProtectApiService.NewRotateKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)
			// MANUAL: Replaced CreateMockReader with an empty JSON body "{}".
			// RotateKey requires no body fields; an empty object is the correct payload.
			rotateKeyOptions.SetKeyActionRotateBody(io.NopCloser(strings.NewReader(`{}`)))

			response, err := ibmKeyProtectApiService.RotateKey(rotateKeyOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from RotateKey(): %d\n", response.StatusCode)
			}

			// end-rotateKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		// MANUAL: DisableKey placed before EnableKey so the timestamp can be recorded
		// and the 31-second rate-limit wait in EnableKey works correctly.
		// The generated file had EnableKey before DisableKey.
		It(`DisableKey request example`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-disableKey

			disableKeyOptions := ibmKeyProtectApiService.NewDisableKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.DisableKey(disableKeyOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DisableKey(): %d\n", response.StatusCode)
			}

			// end-disableKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
			exampleDisableTS = time.Now() // MANUAL: Record timestamp so EnableKey can enforce the rate limit.
		})
		It(`EnableKey request example`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// MANUAL: Wait at least 31 seconds after DisableKey to respect the API rate limit.
			// The generated code had no awareness of this constraint.
			if !exampleDisableTS.IsZero() {
				elapsed := time.Since(exampleDisableTS)
				if elapsed < 31*time.Second {
					fmt.Printf("Waiting %v for rate limit after DisableKey\n", 31*time.Second-elapsed)
					time.Sleep(31*time.Second - elapsed)
				}
			}
			// begin-enableKey

			enableKeyOptions := ibmKeyProtectApiService.NewEnableKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.EnableKey(enableKeyOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from EnableKey(): %d\n", response.StatusCode)
			}

			// end-enableKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`PutPolicy request example`, func() {
			fmt.Println("\nPutPolicy() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID2.
			// Policies must be set on the key that was created with policy overrides, not the standard key.
			if exampleKeyID2 == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			// begin-putPolicy

			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.policy+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			keyPolicyDualAuthDeleteDualAuthDeleteModel := &ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete{
				// MANUAL: Changed from true to false — enabling dual-auth-delete in examples would
				// require a second actor to approve deletion, breaking subsequent cleanup.
				Enabled: core.BoolPtr(false),
			}

			keyPolicyDualAuthDeleteModel := &ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{
				Type:           core.StringPtr("application/vnd.ibm.kms.policy+json"),
				DualAuthDelete: keyPolicyDualAuthDeleteDualAuthDeleteModel,
			}

			setKeyPoliciesOneOfModel := &ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete{
				Metadata:  collectionMetadataModel,
				Resources: []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel},
			}

			putPolicyOptions := ibmKeyProtectApiService.NewPutPolicyOptions(
				exampleKeyID2,
				exampleBluemixInstance,
				setKeyPoliciesOneOfModel,
			)
			putPolicyOptions.SetPolicy("dualAuthDelete") // MANUAL: Added — generated code did not set a policy filter.

			getKeyPoliciesOneOf, response, err := ibmKeyProtectApiService.PutPolicy(putPolicyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(getKeyPoliciesOneOf, "", "  ")
			fmt.Println(string(b))

			// end-putPolicy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKeyPoliciesOneOf).ToNot(BeNil())
		})
		It(`GetPolicy request example`, func() {
			fmt.Println("\nGetPolicy() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID2.
			if exampleKeyID2 == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			// begin-getPolicy

			getPolicyOptions := ibmKeyProtectApiService.NewGetPolicyOptions(
				exampleKeyID2,
				exampleBluemixInstance,
			)
			getPolicyOptions.SetPolicy("dualAuthDelete") // MANUAL: Added — generated code did not set a policy filter.

			getKeyPoliciesOneOf, response, err := ibmKeyProtectApiService.GetPolicy(getPolicyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(getKeyPoliciesOneOf, "", "  ")
			fmt.Println(string(b))

			// end-getPolicy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKeyPoliciesOneOf).ToNot(BeNil())
		})
		It(`PutInstancePolicy request example`, func() {
			// begin-putInstancePolicy

			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.policy+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			instancePolicyAllowedNetworkPolicyDataAttributesModel := &ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyDataAttributes{
				// MANUAL: Changed from "private-only" to "public-and-private".
				// Using "private-only" would lock out public API access, breaking the rest of the suite.
				AllowedNetwork: core.StringPtr("public-and-private"),
			}

			instancePolicyAllowedNetworkPolicyDataModel := &ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData{
				Enabled:    core.BoolPtr(true),
				Attributes: instancePolicyAllowedNetworkPolicyDataAttributesModel,
			}

			setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel := &ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem{
				PolicyType: core.StringPtr("allowedNetwork"),
				PolicyData: instancePolicyAllowedNetworkPolicyDataModel,
			}

			setInstancePoliciesOneOfModel := &ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork{
				Metadata:  collectionMetadataModel,
				Resources: []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem{*setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel},
			}

			putInstancePolicyOptions := ibmKeyProtectApiService.NewPutInstancePolicyOptions(
				exampleBluemixInstance,
				setInstancePoliciesOneOfModel,
			)
			putInstancePolicyOptions.SetPolicy("allowedNetwork") // MANUAL: Added — generated code did not set a policy filter.

			response, err := ibmKeyProtectApiService.PutInstancePolicy(putInstancePolicyOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from PutInstancePolicy(): %d\n", response.StatusCode)
			}

			// end-putInstancePolicy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`GetInstancePolicy request example`, func() {
			fmt.Println("\nGetInstancePolicy() result:")
			// begin-getInstancePolicy

			getInstancePolicyOptions := ibmKeyProtectApiService.NewGetInstancePolicyOptions(
				exampleBluemixInstance,
			)
			getInstancePolicyOptions.SetPolicy("allowedNetwork") // MANUAL: Added — generated code did not set a policy filter.

			getInstancePoliciesOneOf, response, err := ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(getInstancePoliciesOneOf, "", "  ")
			fmt.Println(string(b))

			// end-getInstancePolicy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getInstancePoliciesOneOf).ToNot(BeNil())
		})
		It(`GetAllowedIPPort request example`, func() {
			// begin-getAllowedIPPort

			// Note: GetAllowedIPPort requires the instance to have an allowedIP policy
			// with a private-only network. Skip this example in standard environments.
			Skip("Skipping GetAllowedIPPort — requires instance policy to be private")

			getAllowedIpPortOptions := ibmKeyProtectApiService.NewGetAllowedIPPortOptions(
				exampleBluemixInstance,
			)

			allowedIpPort, response, err := ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(allowedIpPort, "", "  ")
			fmt.Println(string(b))

			// end-getAllowedIPPort

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(allowedIpPort).ToNot(BeNil())
		})
		It(`PostImportToken request example`, func() {
			fmt.Println("\nPostImportToken() result:")
			// begin-postImportToken

			postImportTokenOptions := ibmKeyProtectApiService.NewPostImportTokenOptions(
				exampleBluemixInstance,
			)
			// MANUAL: Added expiration and max-retrievals — generated code set none, creating unlimited tokens.
			postImportTokenOptions.SetExpiration(float64(600))
			postImportTokenOptions.SetMaxAllowedRetrievals(float64(1))

			importToken, response, err := ibmKeyProtectApiService.PostImportToken(postImportTokenOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(importToken, "", "  ")
			fmt.Println(string(b))

			// end-postImportToken

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(importToken).ToNot(BeNil())
		})
		It(`GetImportToken request example`, func() {
			fmt.Println("\nGetImportToken() result:")
			// begin-getImportToken

			getImportTokenOptions := ibmKeyProtectApiService.NewGetImportTokenOptions(
				exampleBluemixInstance,
			)

			getImportToken, response, err := ibmKeyProtectApiService.GetImportToken(getImportTokenOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(getImportToken, "", "  ")
			fmt.Println(string(b))

			// end-getImportToken

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getImportToken).ToNot(BeNil())
		})
		It(`GetRegistrations request example`, func() {
			fmt.Println("\nGetRegistrations() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			// Also removed the hardcoded placeholder CRN query that would return no results.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-getRegistrations

			getRegistrationsOptions := ibmKeyProtectApiService.NewGetRegistrationsOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)

			registrationWithTotalCount, response, err := ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(registrationWithTotalCount, "", "  ")
			fmt.Println(string(b))

			// end-getRegistrations

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(registrationWithTotalCount).ToNot(BeNil())
		})
		It(`GetRegistrationsAllKeys request example`, func() {
			fmt.Println("\nGetRegistrationsAllKeys() result:")
			// begin-getRegistrationsAllKeys

			getRegistrationsAllKeysOptions := ibmKeyProtectApiService.NewGetRegistrationsAllKeysOptions(
				exampleBluemixInstance,
			)

			registrationWithTotalCount, response, err := ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(registrationWithTotalCount, "", "  ")
			fmt.Println(string(b))

			// end-getRegistrationsAllKeys

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(registrationWithTotalCount).ToNot(BeNil())
		})
		It(`CreateKeyAlias request example`, func() {
			fmt.Println("\nCreateKeyAlias() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			// Alias value set to a valid name; status code fixed from 200 to 201.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-createKeyAlias

			createKeyAliasOptions := ibmKeyProtectApiService.NewCreateKeyAliasOptions(
				exampleKeyID,
				"exampleKeyAlias",
				exampleBluemixInstance,
			)

			keyAlias, response, err := ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(keyAlias, "", "  ")
			fmt.Println(string(b))

			// end-createKeyAlias

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(keyAlias).ToNot(BeNil())
		})
		// MANUAL: DeleteKeyAlias moved to immediately after CreateKeyAlias so the alias is cleaned up
		// while the key is still active. In the generated file it appeared at the very end.
		It(`DeleteKeyAlias request example`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-deleteKeyAlias

			deleteKeyAliasOptions := ibmKeyProtectApiService.NewDeleteKeyAliasOptions(
				exampleKeyID,
				"exampleKeyAlias",
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.DeleteKeyAlias(deleteKeyAliasOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteKeyAlias(): %d\n", response.StatusCode)
			}

			// end-deleteKeyAlias

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`ListKeyRings request example`, func() {
			fmt.Println("\nListKeyRings() result:")
			// begin-listKeyRings

			listKeyRingsOptions := ibmKeyProtectApiService.NewListKeyRingsOptions(
				exampleBluemixInstance,
			)

			listKeyRingsWithTotalCount, response, err := ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKeyRingsWithTotalCount, "", "  ")
			fmt.Println(string(b))

			// end-listKeyRings

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKeyRingsWithTotalCount).ToNot(BeNil())
		})
		It(`GetKmipAdapters request example`, func() {
			fmt.Println("\nGetKmipAdapters() result:")
			// begin-get_kmip_adapters

			getKmipAdaptersOptions := ibmKeyProtectApiService.NewGetKmipAdaptersOptions(
				exampleBluemixInstance,
			)

			listKmipAdaptersWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipAdaptersWithTotalCount, "", "  ")
			fmt.Println(string(b))

			// end-get_kmip_adapters

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipAdaptersWithTotalCount).ToNot(BeNil())
		})
		// MANUAL: CreateKeyRing placed after GetKmipAdapters and before PatchKey so the ring
		// exists when PatchKey moves the key into it.
		It(`CreateKeyRing request example`, func() {
			// begin-createKeyRing

			// MANUAL: ID changed from "testString" to exampleKeyringID.
			createKeyRingOptions := ibmKeyProtectApiService.NewCreateKeyRingOptions(
				exampleKeyringID,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.CreateKeyRing(createKeyRingOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 201 {
				fmt.Printf("\nUnexpected response status code received from CreateKeyRing(): %d\n", response.StatusCode)
			}

			// end-createKeyRing

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
		})
		// MANUAL: PatchKey placed after CreateKeyRing so the target ring already exists,
		// and before DeleteKey so the key is in the correct ring when deleted.
		It(`PatchKey request example`, func() {
			fmt.Println("\nPatchKey() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-patchKey

			// MANUAL: Replaced CreateMockReader with a real JSON body that moves the key into the example ring.
			keyPatchBodyJSON, _ := json.Marshal(map[string]interface{}{"keyRingID": exampleKeyringID})

			patchKeyOptions := ibmKeyProtectApiService.NewPatchKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)
			patchKeyOptions.SetKeyPatchBody(io.NopCloser(strings.NewReader(string(keyPatchBodyJSON))))

			patchKeyResponseBody, response, err := ibmKeyProtectApiService.PatchKey(patchKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(patchKeyResponseBody, "", "  ")
			fmt.Println(string(b))

			// end-patchKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(patchKeyResponseBody).ToNot(BeNil())
		})
		It(`DeleteKey request example`, func() {
			fmt.Println("\nDeleteKey() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			// Added ring, prefer, and force options to match a real delete call.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-deleteKey

			deleteKeyOptions := ibmKeyProtectApiService.NewDeleteKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)
			deleteKeyOptions.SetXKmsKeyRing(exampleKeyringID)
			deleteKeyOptions.SetPrefer("return=representation")
			deleteKeyOptions.SetForce(false)

			deleteKey, response, err := ibmKeyProtectApiService.DeleteKey(deleteKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(deleteKey, "", "  ")
			fmt.Println(string(b))

			// end-deleteKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(deleteKey).ToNot(BeNil())
			exampleDeleteTS = time.Now() // MANUAL: Record timestamp so RestoreKey can enforce the rate limit.
		})
		It(`RestoreKey request example`, func() {
			fmt.Println("\nRestoreKey() result:")
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID.
			// Moved to immediately after DeleteKey; added ring and prefer options.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// MANUAL: Wait at least 31 seconds after DeleteKey to respect the API rate limit.
			// The generated code had no awareness of this constraint.
			if !exampleDeleteTS.IsZero() {
				elapsed := time.Since(exampleDeleteTS)
				if elapsed < 31*time.Second {
					fmt.Printf("Waiting %v for rate limit after DeleteKey\n", 31*time.Second-elapsed)
					time.Sleep(31*time.Second - elapsed)
				}
			}
			// begin-restoreKey

			restoreKeyOptions := ibmKeyProtectApiService.NewRestoreKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)
			restoreKeyOptions.SetXKmsKeyRing(exampleKeyringID)
			restoreKeyOptions.SetPrefer("return=representation")

			result, response, err := ibmKeyProtectApiService.RestoreKey(restoreKeyOptions)
			if err != nil {
				panic(err)
			}
			if result != nil {
				defer result.Close()
			}

			// end-restoreKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(result).ToNot(BeNil())
		})
		// MANUAL: DeleteKeyRing expanded into a two-step operation: first patch the key back to
		// the "default" ring (so the ring has no keys), then delete it.
		// Without this, DeleteKeyRing fails because the ring is non-empty.
		It(`DeleteKeyRing request example`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyringID.
			if exampleKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// begin-deleteKeyRing

			// MANUAL: First move the key back to the default ring so the ring becomes empty.
			keyPatchBodyJSON, _ := json.Marshal(map[string]interface{}{"keyRingID": "default"})
			patchOpts := ibmKeyProtectApiService.NewPatchKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)
			patchOpts.SetXKmsKeyRing(exampleKeyringID)
			patchOpts.SetKeyPatchBody(io.NopCloser(strings.NewReader(string(keyPatchBodyJSON))))
			_, _, _ = ibmKeyProtectApiService.PatchKey(patchOpts)

			deleteKeyRingOptions := ibmKeyProtectApiService.NewDeleteKeyRingOptions(
				exampleKeyringID,
				exampleBluemixInstance,
			)
			deleteKeyRingOptions.SetForce(false)

			response, err := ibmKeyProtectApiService.DeleteKeyRing(deleteKeyRingOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteKeyRing(): %d\n", response.StatusCode)
			}

			// end-deleteKeyRing

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`PurgeKey request example`, func() {
			// begin-purgeKey

			// Note: PurgeKey requires the key to have been in the deleted state for at least 4 hours.
			Skip("Skipping PurgeKey — requires 4-hour wait after deletion")

			purgeKeyOptions := ibmKeyProtectApiService.NewPurgeKeyOptions(
				exampleKeyID,
				exampleBluemixInstance,
			)
			purgeKeyOptions.SetXKmsKeyRing(exampleKeyringID)
			purgeKeyOptions.SetPrefer("return=representation")

			purgeKey, response, err := ibmKeyProtectApiService.PurgeKey(purgeKeyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(purgeKey, "", "  ")
			fmt.Println(string(b))

			// end-purgeKey

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(purgeKey).ToNot(BeNil())
		})
		It(`SetKeyForDeletion request example`, func() {
			// begin-setKeyForDeletion

			// Note: SetKeyForDeletion requires dual-auth-delete policy to be enabled on the key.
			// This is disruptive in test environments — skip by default.
			Skip("Skipping SetKeyForDeletion — requires dual-auth policy, disruptive")

			setKeyForDeletionOptions := ibmKeyProtectApiService.NewSetKeyForDeletionOptions(
				exampleKeyID2,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.SetKeyForDeletion(setKeyForDeletionOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from SetKeyForDeletion(): %d\n", response.StatusCode)
			}

			// end-setKeyForDeletion

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`UnsetKeyForDeletion request example`, func() {
			// begin-unsetKeyForDeletion

			// Note: UnsetKeyForDeletion requires dual-auth-delete policy to be enabled on the key.
			// This is disruptive in test environments — skip by default.
			Skip("Skipping UnsetKeyForDeletion — requires dual-auth policy, disruptive")

			unsetKeyForDeletionOptions := ibmKeyProtectApiService.NewUnsetKeyForDeletionOptions(
				exampleKeyID2,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.UnsetKeyForDeletion(unsetKeyForDeletionOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from UnsetKeyForDeletion(): %d\n", response.StatusCode)
			}

			// end-unsetKeyForDeletion

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`SyncAssociatedResources request example`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to exampleKeyID2.
			if exampleKeyID2 == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			// begin-syncAssociatedResources

			syncAssociatedResourcesOptions := ibmKeyProtectApiService.NewSyncAssociatedResourcesOptions(
				exampleKeyID2,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.SyncAssociatedResources(syncAssociatedResourcesOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from SyncAssociatedResources(): %d\n", response.StatusCode)
			}

			// end-syncAssociatedResources

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`CreateKmipAdapter request example`, func() {
			fmt.Println("\nCreateKmipAdapter() result:")
			// MANUAL: Skip guard added — KMIP adapter needs a real CRK ID.
			if exampleKeyID2 == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			// begin-create_kmip_adapter

			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			kmipProfileDataBodyModel := &ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative{
				// MANUAL: Changed from hardcoded placeholder UUID "feddecaf-0000-0000-0000-1234567890ab"
				// to the actual exampleKeyID2 created earlier in the example run.
				CrkID: core.StringPtr(exampleKeyID2),
			}

			createKmipAdapterObjectModel := &ibmkeyprotectapiv2.CreateKMIPAdapterObject{
				Name:        core.StringPtr(exampleKmipName),
				Description: core.StringPtr("An example KMIP adapter"),
				Profile:     core.StringPtr("native_1.0"),
				ProfileData: kmipProfileDataBodyModel,
			}

			createKmipAdapterOptions := ibmKeyProtectApiService.NewCreateKmipAdapterOptions(
				exampleBluemixInstance,
				collectionMetadataModel,
				[]ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel},
			)

			listKmipAdapters, response, err := ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipAdapters, "", "  ")
			fmt.Println(string(b))

			// end-create_kmip_adapter

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(listKmipAdapters).ToNot(BeNil())
		})
		It(`GetKmipAdapter request example`, func() {
			fmt.Println("\nGetKmipAdapter() result:")
			// begin-get_kmip_adapter

			getKmipAdapterOptions := ibmKeyProtectApiService.NewGetKmipAdapterOptions(
				exampleKmipName,
				exampleBluemixInstance,
			)

			listKmipAdapters, response, err := ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipAdapters, "", "  ")
			fmt.Println(string(b))

			// end-get_kmip_adapter

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipAdapters).ToNot(BeNil())
		})
		It(`GetKmipObjects request example`, func() {
			fmt.Println("\nGetKmipObjects() result:")
			// begin-get_kmip_objects

			getKmipObjectsOptions := ibmKeyProtectApiService.NewGetKmipObjectsOptions(
				exampleKmipName,
				exampleBluemixInstance,
			)

			listKmipObjectsWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipObjectsWithTotalCount, "", "  ")
			fmt.Println(string(b))

			// end-get_kmip_objects

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipObjectsWithTotalCount).ToNot(BeNil())
		})
		It(`GetKmipObject request example`, func() {
			// begin-get_kmip_object

			// Note: GetKmipObject requires an existing KMIP object ID.
			// Skip this example if no KMIP object has been created.
			Skip("Skipping GetKmipObject — no KMIP object created during example run")

			getKmipObjectOptions := ibmKeyProtectApiService.NewGetKmipObjectOptions(
				exampleKmipName,
				exampleBluemixInstance,
				"<kmip-object-id>",
			)

			listKmipObjectsWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipObjectsWithTotalCount, "", "  ")
			fmt.Println(string(b))

			// end-get_kmip_object

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipObjectsWithTotalCount).ToNot(BeNil())
		})
		It(`GetKmipClientCertificates request example`, func() {
			fmt.Println("\nGetKmipClientCertificates() result:")
			// begin-get_kmip_client_certificates

			getKmipClientCertificatesOptions := ibmKeyProtectApiService.NewGetKmipClientCertificatesOptions(
				exampleKmipName,
				exampleBluemixInstance,
			)

			listKmipPartialClientCertificatesWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipPartialClientCertificatesWithTotalCount, "", "  ")
			fmt.Println(string(b))

			// end-get_kmip_client_certificates

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipPartialClientCertificatesWithTotalCount).ToNot(BeNil())
		})
		It(`AddKmipClientCertificate request example`, func() {
			fmt.Println("\nAddKmipClientCertificate() result:")
			// begin-add_kmip_client_certificate

			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			createKmipClientCertificateObjectModel := &ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{
				Certificate: core.StringPtr(generateTestCertPEM()), // MANUAL: generated in-process
				Name:        core.StringPtr(exampleKmipCertName),
			}

			addKmipClientCertificateOptions := ibmKeyProtectApiService.NewAddKmipClientCertificateOptions(
				exampleKmipName,
				exampleBluemixInstance,
				collectionMetadataModel,
				[]ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel},
			)

			listKmipClientCertificates, response, err := ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipClientCertificates, "", "  ")
			fmt.Println(string(b))

			// end-add_kmip_client_certificate

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(listKmipClientCertificates).ToNot(BeNil())
		})
		It(`GetKmipClientCertificate request example`, func() {
			fmt.Println("\nGetKmipClientCertificate() result:")
			// begin-get_kmip_client_certificate

			getKmipClientCertificateOptions := ibmKeyProtectApiService.NewGetKmipClientCertificateOptions(
				exampleKmipName,
				exampleKmipCertName,
				exampleBluemixInstance,
			)

			listKmipClientCertificates, response, err := ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(listKmipClientCertificates, "", "  ")
			fmt.Println(string(b))

			// end-get_kmip_client_certificate

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipClientCertificates).ToNot(BeNil())
		})
		It(`DeleteKmipClientCertificate request example`, func() {
			// begin-delete_kmip_client_certificate

			deleteKmipClientCertificateOptions := ibmKeyProtectApiService.NewDeleteKmipClientCertificateOptions(
				exampleKmipName,
				exampleKmipCertName,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.DeleteKmipClientCertificate(deleteKmipClientCertificateOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteKmipClientCertificate(): %d\n", response.StatusCode)
			}

			// end-delete_kmip_client_certificate

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteKmipAdapter request example`, func() {
			// begin-delete_kmip_adapter

			deleteKmipAdapterOptions := ibmKeyProtectApiService.NewDeleteKmipAdapterOptions(
				exampleKmipName,
				exampleBluemixInstance,
			)

			response, err := ibmKeyProtectApiService.DeleteKmipAdapter(deleteKmipAdapterOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteKmipAdapter(): %d\n", response.StatusCode)
			}

			// end-delete_kmip_adapter

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteKmipObject request example`, func() {
			// begin-delete_kmip_object

			// Note: DeleteKmipObject requires an existing KMIP object ID.
			Skip("Skipping DeleteKmipObject — no KMIP object created during example run")

			deleteKmipObjectOptions := ibmKeyProtectApiService.NewDeleteKmipObjectOptions(
				exampleKmipName,
				exampleBluemixInstance,
				"<kmip-object-id>",
			)

			response, err := ibmKeyProtectApiService.DeleteKmipObject(deleteKmipObjectOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteKmipObject(): %d\n", response.StatusCode)
			}

			// end-delete_kmip_object

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	// Cleanup runs after all examples and best-effort deletes all resources created during the
	// run so the instance is left clean. Failures are logged but do not fail the suite.
	Describe(`Cleanup - Remove all resources created during examples`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})

		It(`Best-effort cleanup of created key`, func() {
			if exampleKeyID == "" {
				Skip("No created key ID available, skipping cleanup")
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: deleting created key %s\n", exampleKeyID)
			deleteOpts := &ibmkeyprotectapiv2.DeleteKeyOptions{
				ID:              core.StringPtr(exampleKeyID),
				BluemixInstance: core.StringPtr(exampleBluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
			}
			_, _, deleteErr := ibmKeyProtectApiService.DeleteKey(deleteOpts)
			if deleteErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: delete created key failed (may already be deleted): %v\n", deleteErr)
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: purging created key %s\n", exampleKeyID)
			purgeOpts := &ibmkeyprotectapiv2.PurgeKeyOptions{
				ID:              core.StringPtr(exampleKeyID),
				BluemixInstance: core.StringPtr(exampleBluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
			}
			_, _, purgeErr := ibmKeyProtectApiService.PurgeKey(purgeOpts)
			if purgeErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: purge created key failed (may need 4-hour wait): %v\n", purgeErr)
			}
		})

		It(`Best-effort cleanup of policies-overridden key`, func() {
			if exampleKeyID2 == "" {
				Skip("No policies-overridden key ID available, skipping cleanup")
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: deleting policies-overridden key %s\n", exampleKeyID2)
			deleteOpts := &ibmkeyprotectapiv2.DeleteKeyOptions{
				ID:              core.StringPtr(exampleKeyID2),
				BluemixInstance: core.StringPtr(exampleBluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
				Force:           core.BoolPtr(false),
			}
			_, _, deleteErr := ibmKeyProtectApiService.DeleteKey(deleteOpts)
			if deleteErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: delete policies-overridden key failed (may already be deleted): %v\n", deleteErr)
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: purging policies-overridden key %s\n", exampleKeyID2)
			purgeOpts := &ibmkeyprotectapiv2.PurgeKeyOptions{
				ID:              core.StringPtr(exampleKeyID2),
				BluemixInstance: core.StringPtr(exampleBluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
			}
			_, _, purgeErr := ibmKeyProtectApiService.PurgeKey(purgeOpts)
			if purgeErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: purge policies-overridden key failed (may need 4-hour wait): %v\n", purgeErr)
			}
		})

		It(`Best-effort cleanup of key ring`, func() {
			fmt.Fprintf(GinkgoWriter, "Cleanup: deleting key ring %s\n", exampleKeyringID)
			deleteRingOpts := &ibmkeyprotectapiv2.DeleteKeyRingOptions{
				KeyRingID:       core.StringPtr(exampleKeyringID),
				BluemixInstance: core.StringPtr(exampleBluemixInstance),
				Force:           core.BoolPtr(false),
			}
			_, ringErr := ibmKeyProtectApiService.DeleteKeyRing(deleteRingOpts)
			if ringErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: delete key ring failed (may already be deleted): %v\n", ringErr)
			}
		})
	})
})
