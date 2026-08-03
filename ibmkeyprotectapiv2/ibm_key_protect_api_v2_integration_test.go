//go:build integration

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

// MANUAL: Added "encoding/json", "io", and "strings" imports to support
// constructing real JSON request bodies with io.NopCloser wrappers.
// The generated file only imported "fmt", "log", "os", and "time".
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
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

// MANUAL: Added package-level shared state variables so that resources created
// in early tests (keys, key rings, KMIP adapters) can be referenced by later
// tests without hardcoding IDs. The generated file had no shared state at all —
// every test used the placeholder "testString" for all IDs.
var (
	bluemixInstance         string               // loaded from config BLUEMIX_INSTANCE; replaces "testString" in every BluemixInstance field
	createdKeyID            string               // populated by CreateKey; used by all single-key tests
	policiesOverriddenKeyID string               // populated by CreateKeyWithPoliciesOverrides; used by policy/KMIP tests
	ciphertext              string               // populated by WrapKey; used by UnwrapKey and RewrapKey
	createdKeyringID        = "test-keyring"     // constant name for the test key ring
	kmipName                = "test-kmip"        // constant name for the test KMIP adapter
	kmipCertName            = "Test-certificate" // constant name for the test KMIP client certificate
	disableKeyTimestamp     time.Time            // set by DisableKey; used by EnableKey to enforce the 31-second API rate limit
	deleteKeyTimestamp      time.Time            // set by DeleteKey; used by RestoreKey to enforce the 31-second API rate limit
)

/**
 * This file contains an integration test for the ibmkeyprotectapiv2 package.
 *
 * Notes:
 *
 * The integration test will automatically skip tests if the required config file is not available.
 * Config file requires:
 *
 *	IBM_KEY_PROTECT_API_URL=https://qa.<region>.kms.test.cloud.ibm.com
 *	IBM_KEY_PROTECT_API_AUTH_TYPE=iam
 *	IBM_KEY_PROTECT_API_APIKEY=<api-key>
 *	IBM_KEY_PROTECT_API_AUTH_URL=https://iam.test.cloud.ibm.com
 *	IBM_KEY_PROTECT_API_BLUEMIX_INSTANCE=<created-instance-id>
 *
 */

var _ = Describe(`IbmKeyProtectApiV2 Integration Tests`, func() {
	// MANUAL: Path changed from "../ibm_key_protect_api_v2.env" to "./ibm_key_protect_api_v2.env"
	// to match the location of the env file when tests are run from the ibmkeyprotectapiv2/ directory.
	const externalConfigFile = "./ibm_key_protect_api_v2.env"

	var (
		err                     error
		ibmKeyProtectApiService *ibmkeyprotectapiv2.IbmKeyProtectApiV2
		serviceURL              string
		config                  map[string]string
	)

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping tests...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping tests: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(ibmkeyprotectapiv2.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping tests: " + err.Error())
			}
			serviceURL = config["URL"]
			if serviceURL == "" {
				Skip("Unable to load service URL configuration property, skipping tests")
			}

			// MANUAL: Load BLUEMIX_INSTANCE from config and store in the shared state variable.
			// The generated code had no concept of a shared instance ID; every test hardcoded "testString".
			bluemixInstance = config["BLUEMIX_INSTANCE"]
			if bluemixInstance == "" {
				Skip("Unable to load BLUEMIX_INSTANCE configuration property, skipping tests")
			}

			fmt.Fprintf(GinkgoWriter, "Service URL: %v\n", serviceURL)
			fmt.Fprintf(GinkgoWriter, "Bluemix Instance: %v\n", bluemixInstance) // MANUAL: Added instance ID logging
			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {
			ibmKeyProtectApiServiceOptions := &ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{}

			ibmKeyProtectApiService, err = ibmkeyprotectapiv2.NewIbmKeyProtectApiV2UsingExternalConfig(ibmKeyProtectApiServiceOptions)
			Expect(err).To(BeNil())
			Expect(ibmKeyProtectApiService).ToNot(BeNil())
			Expect(ibmKeyProtectApiService.Service.Options.URL).To(Equal(serviceURL))

			core.SetLogger(core.NewLogger(core.LevelDebug, log.New(GinkgoWriter, "", log.LstdFlags), log.New(GinkgoWriter, "", log.LstdFlags)))
			ibmKeyProtectApiService.EnableRetries(4, 30*time.Second)
		})
	})

	Describe(`GetKeyCollectionMetadata - Retrieve key total`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKeyCollectionMetadata(getKeyCollectionMetadataOptions *GetKeyCollectionMetadataOptions)`, func() {
			getKeyCollectionMetadataOptions := &ibmkeyprotectapiv2.GetKeyCollectionMetadataOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				State:           []int64{0, 1, 2, 3},
				Extractable:     core.BoolPtr(true),
				// MANUAL: Removed CorrelationID, Filter, XKmsKeyRing — generated code set these to "testString"
				// which would cause the API to filter by a ring/correlation that doesn't exist.
			}

			response, err := ibmKeyProtectApiService.GetKeyCollectionMetadata(getKeyCollectionMetadataOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
		})
	})

	Describe(`CreateKey - Create a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateKey(createKeyOptions *CreateKeyOptions)`, func() {
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
						"name":        "created-test-root-key",
						"description": "A Key Protect key used for integration testing",
						"extractable": false,
					},
				},
			}
			keyCreateBodyJSON, _ := json.Marshal(keyCreateBody)

			createKeyOptions := &ibmkeyprotectapiv2.CreateKeyOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: io.NopCloser wraps *strings.Reader to satisfy the io.ReadCloser interface
				// required by the SDK; strings.NewReader alone does not implement Close().
				KeyCreateBody: io.NopCloser(strings.NewReader(string(keyCreateBodyJSON))),
				Prefer:        core.StringPtr("return=representation"),
				// MANUAL: Removed CorrelationID and XKmsKeyRing — generated code set these to "testString".
			}

			key, response, err := ibmKeyProtectApiService.CreateKey(createKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(key).ToNot(BeNil())

			// MANUAL: Extract and store the created key ID for use in all subsequent tests.
			// The generated code did not capture the response at all.
			Expect(len(key.Resources)).To(BeNumerically(">", 0))
			createdKeyID = *key.Resources[0].ID
			fmt.Fprintf(GinkgoWriter, "Created Key ID: %s\n", createdKeyID)
		})
	})

	Describe(`GetKeys - List keys`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKeys(getKeysOptions *GetKeysOptions)`, func() {
			getKeysOptions := &ibmkeyprotectapiv2.GetKeysOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID, Search, Filter, XKmsKeyRing — generated code set all
				// of these to "testString", causing filters that would return no results or errors.
			}

			listKeys, response, err := ibmKeyProtectApiService.GetKeys(getKeysOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKeys).ToNot(BeNil())
		})
	})

	Describe(`CreateKeyWithPoliciesOverrides - Create a key with policy overrides`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptions *CreateKeyWithPoliciesOverridesOptions)`, func() {
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
						"name":        "policies-test-overriden-key",
						"description": "A Key Protect key used for integration testing",
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

			createKeyWithPoliciesOverridesOptions := &ibmkeyprotectapiv2.CreateKeyWithPoliciesOverridesOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: io.NopCloser wraps *strings.Reader to satisfy io.ReadCloser.
				KeyWithPolicyOverridesCreateBody: io.NopCloser(strings.NewReader(string(keyWithPolicyOverridesCreateBodyJSON))),
				Prefer:                           core.StringPtr("return=representation"),
				// MANUAL: Removed CorrelationID, XKmsKeyRing — generated code set these to "testString".
			}

			key, response, err := ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(key).ToNot(BeNil())

			// MANUAL: Extract and store the policies-overridden key ID.
			// Used by PutPolicy, GetPolicy, SyncAssociatedResources, CreateKmipAdapter,
			// SetKeyForDeletion, and UnsetKeyForDeletion.
			Expect(len(key.Resources)).To(BeNumerically(">", 0))
			policiesOverriddenKeyID = *key.Resources[0].ID
			fmt.Fprintf(GinkgoWriter, "Policies-Overridden Key ID: %s\n", policiesOverriddenKeyID)
		})
	})

	Describe(`GetKey - Retrieve a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKey(getKeyOptions *GetKeyOptions)`, func() {
			// MANUAL: Skip guard — generated code used "testString" which would 404.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			getKeyOptions := &ibmkeyprotectapiv2.GetKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			getKey, response, err := ibmKeyProtectApiService.GetKey(getKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKey).ToNot(BeNil())
		})
	})

	// MANUAL: Removed the ActionOnKey test block entirely. The generated code called
	// ActionOnKey("disable") with a mock body against "testString" ID. This endpoint
	// is not exercised in the Python integration tests; DisableKey and EnableKey are
	// called individually instead.

	Describe(`GetKeyMetadata - Retrieve key metadata`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKeyMetadata(getKeyMetadataOptions *GetKeyMetadataOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			getKeyMetadataOptions := &ibmkeyprotectapiv2.GetKeyMetadataOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			getKeyMetadata, response, err := ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKeyMetadata).ToNot(BeNil())
		})
	})

	Describe(`GetKeyVersions - List key versions`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKeyVersions(getKeyVersionsOptions *GetKeyVersionsOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			getKeyVersionsOptions := &ibmkeyprotectapiv2.GetKeyVersionsOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				Limit:           core.Int64Ptr(int64(200)),
				Offset:          core.Int64Ptr(int64(0)),
				TotalCount:      core.BoolPtr(true),
				AllKeyStates:    core.BoolPtr(false),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			listKeyVersions, response, err := ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKeyVersions).ToNot(BeNil())
		})
	})

	Describe(`WrapKey - Wrap a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`WrapKey(wrapKeyOptions *WrapKeyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// MANUAL: Replaced CreateMockReader with a real JSON body containing a base64 plaintext.
			keyActionWrapBody := map[string]interface{}{
				"plaintext": "cGxhaW50ZXh0LWRhdGEta2V5",
			}
			keyActionWrapBodyJSON, _ := json.Marshal(keyActionWrapBody)

			wrapKeyOptions := &ibmkeyprotectapiv2.WrapKeyOptions{
				ID:                core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance:   core.StringPtr(bluemixInstance),
				KeyActionWrapBody: io.NopCloser(strings.NewReader(string(keyActionWrapBodyJSON))),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			wrapKeyResponseBody, response, err := ibmKeyProtectApiService.WrapKey(wrapKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(wrapKeyResponseBody).ToNot(BeNil())

			// MANUAL: Extract and store the returned ciphertext for use in UnwrapKey and RewrapKey.
			// The generated code did not capture the response at all.
			Expect(wrapKeyResponseBody.Ciphertext).ToNot(BeNil())
			ciphertext = *wrapKeyResponseBody.Ciphertext
			fmt.Fprintf(GinkgoWriter, "Stored ciphertext for unwrap/rewrap\n")
		})
	})

	Describe(`UnwrapKey - Unwrap a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UnwrapKey(unwrapKeyOptions *UnwrapKeyOptions)`, func() {
			// MANUAL: Skip guards added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			if ciphertext == "" {
				Skip("No ciphertext available from WrapKey, skipping")
			}
			// MANUAL: Replaced CreateMockReader with a real JSON body using the stored ciphertext.
			keyActionUnwrapBody := map[string]interface{}{
				"ciphertext": ciphertext,
			}
			keyActionUnwrapBodyJSON, _ := json.Marshal(keyActionUnwrapBody)

			unwrapKeyOptions := &ibmkeyprotectapiv2.UnwrapKeyOptions{
				ID:                  core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance:     core.StringPtr(bluemixInstance),
				KeyActionUnwrapBody: io.NopCloser(strings.NewReader(string(keyActionUnwrapBodyJSON))),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			unwrapKeyResponseBody, response, err := ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(unwrapKeyResponseBody).ToNot(BeNil())
		})
	})

	Describe(`RewrapKey - Rewrap a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`RewrapKey(rewrapKeyOptions *RewrapKeyOptions)`, func() {
			// MANUAL: Skip guards added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			if ciphertext == "" {
				Skip("No ciphertext available from WrapKey, skipping")
			}
			// MANUAL: Replaced CreateMockReader with a real JSON body using the stored ciphertext.
			keyActionRewrapBody := map[string]interface{}{
				"ciphertext": ciphertext,
			}
			keyActionRewrapBodyJSON, _ := json.Marshal(keyActionRewrapBody)

			rewrapKeyOptions := &ibmkeyprotectapiv2.RewrapKeyOptions{
				ID:                  core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance:     core.StringPtr(bluemixInstance),
				KeyActionRewrapBody: io.NopCloser(strings.NewReader(string(keyActionRewrapBodyJSON))),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			rewrapKeyResponseBody, response, err := ibmKeyProtectApiService.RewrapKey(rewrapKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(rewrapKeyResponseBody).ToNot(BeNil())
		})
	})

	Describe(`RotateKey - Rotate a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`RotateKey(rotateKeyOptions *RotateKeyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			rotateKeyOptions := &ibmkeyprotectapiv2.RotateKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Replaced CreateMockReader with an empty JSON body "{}".
				// RotateKey requires no body fields; an empty object is the correct payload.
				KeyActionRotateBody: io.NopCloser(strings.NewReader(`{}`)),
				Prefer:              core.StringPtr("return=representation"),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			response, err := ibmKeyProtectApiService.RotateKey(rotateKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	// MANUAL: Moved DisableKey before EnableKey so the timestamp can be recorded
	// and the 31-second rate-limit wait in EnableKey works correctly.
	// The generated file had EnableKey before DisableKey.
	Describe(`DisableKey - Disable a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DisableKey(disableKeyOptions *DisableKeyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			disableKeyOptions := &ibmkeyprotectapiv2.DisableKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			response, err := ibmKeyProtectApiService.DisableKey(disableKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
			// MANUAL: Record timestamp so EnableKey can enforce the API's 30-second rate limit.
			disableKeyTimestamp = time.Now()
		})
	})

	Describe(`EnableKey - Enable a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`EnableKey(enableKeyOptions *EnableKeyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// MANUAL: Wait at least 31 seconds after DisableKey to respect the API rate limit.
			// The generated code had no awareness of this constraint.
			if !disableKeyTimestamp.IsZero() {
				elapsed := time.Since(disableKeyTimestamp)
				if elapsed < 31*time.Second {
					fmt.Fprintf(GinkgoWriter, "Waiting %v for rate limit after DisableKey\n", 31*time.Second-elapsed)
					time.Sleep(31*time.Second - elapsed)
				}
			}
			enableKeyOptions := &ibmkeyprotectapiv2.EnableKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			response, err := ibmKeyProtectApiService.EnableKey(enableKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`PutPolicy - Set key policies`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PutPolicy(putPolicyOptions *PutPolicyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to policiesOverriddenKeyID.
			// Policies must be set on the key that was created with policy overrides, not the standard key.
			if policiesOverriddenKeyID == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.policy+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			keyPolicyDualAuthDeleteDualAuthDeleteModel := &ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete{
				// MANUAL: Changed from true to false — enabling dual-auth-delete in tests would
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

			putPolicyOptions := &ibmkeyprotectapiv2.PutPolicyOptions{
				ID:               core.StringPtr(policiesOverriddenKeyID), // MANUAL: was "testString"
				BluemixInstance:  core.StringPtr(bluemixInstance),
				KeyPolicyPutBody: setKeyPoliciesOneOfModel,
				Policy:           core.StringPtr("dualAuthDelete"),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			getKeyPoliciesOneOf, response, err := ibmKeyProtectApiService.PutPolicy(putPolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKeyPoliciesOneOf).ToNot(BeNil())
		})
	})

	Describe(`GetPolicy - List key policies`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetPolicy(getPolicyOptions *GetPolicyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to policiesOverriddenKeyID.
			if policiesOverriddenKeyID == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			getPolicyOptions := &ibmkeyprotectapiv2.GetPolicyOptions{
				ID:              core.StringPtr(policiesOverriddenKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				Policy:          core.StringPtr("dualAuthDelete"),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			getKeyPoliciesOneOf, response, err := ibmKeyProtectApiService.GetPolicy(getPolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getKeyPoliciesOneOf).ToNot(BeNil())
		})
	})

	Describe(`PutInstancePolicy - Set instance policies`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PutInstancePolicy(putInstancePolicyOptions *PutInstancePolicyOptions)`, func() {
			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.policy+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			instancePolicyAllowedNetworkPolicyDataAttributesModel := &ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyDataAttributes{
				// MANUAL: Changed from "private-only" to "public-and-private".
				// Using "private-only" in tests would lock out public API access, breaking the rest of the suite.
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

			putInstancePolicyOptions := &ibmkeyprotectapiv2.PutInstancePolicyOptions{
				BluemixInstance:       core.StringPtr(bluemixInstance),
				InstancePolicyPutBody: setInstancePoliciesOneOfModel,
				Policy:                core.StringPtr("allowedNetwork"),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			response, err := ibmKeyProtectApiService.PutInstancePolicy(putInstancePolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`GetInstancePolicy - List instance policies`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetInstancePolicy(getInstancePolicyOptions *GetInstancePolicyOptions)`, func() {
			getInstancePolicyOptions := &ibmkeyprotectapiv2.GetInstancePolicyOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				Policy:          core.StringPtr("allowedNetwork"),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			getInstancePoliciesOneOf, response, err := ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getInstancePoliciesOneOf).ToNot(BeNil())
		})
	})

	Describe(`GetAllowedIPPort - Retrieve allowed IP port`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetAllowedIPPort(getAllowedIPPortOptions *GetAllowedIPPortOptions)`, func() {
			// MANUAL: Skip added — this endpoint only works when the instance has an allowedIP
			// policy active with a private-only network. Running it in a standard test environment fails.
			Skip("Skipping GetAllowedIPPort — requires instance policy to be private")
			getAllowedIpPortOptions := &ibmkeyprotectapiv2.GetAllowedIPPortOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			allowedIpPort, response, err := ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(allowedIpPort).ToNot(BeNil())
		})
	})

	Describe(`PostImportToken - Create an import token`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PostImportToken(postImportTokenOptions *PostImportTokenOptions)`, func() {
			postImportTokenOptions := &ibmkeyprotectapiv2.PostImportTokenOptions{
				BluemixInstance:      core.StringPtr(bluemixInstance),
				Expiration:           core.Float64Ptr(float64(600)),
				MaxAllowedRetrievals: core.Float64Ptr(float64(1)),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			importToken, response, err := ibmKeyProtectApiService.PostImportToken(postImportTokenOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(importToken).ToNot(BeNil())
		})
	})

	Describe(`GetImportToken - Retrieve an import token`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetImportToken(getImportTokenOptions *GetImportTokenOptions)`, func() {
			getImportTokenOptions := &ibmkeyprotectapiv2.GetImportTokenOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			getImportToken, response, err := ibmKeyProtectApiService.GetImportToken(getImportTokenOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(getImportToken).ToNot(BeNil())
		})
	})

	Describe(`GetRegistrations - List registrations for a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetRegistrations(getRegistrationsOptions *GetRegistrationsOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			getRegistrationsOptions := &ibmkeyprotectapiv2.GetRegistrationsOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID, XKmsKeyRing, UrlEncodedResourceCRNQuery,
				// PreventKeyDeletion, TotalCount — generated code set string fields to "testString"
				// which would cause malformed CRN filter errors.
			}

			registrationWithTotalCount, response, err := ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(registrationWithTotalCount).ToNot(BeNil())
		})
	})

	Describe(`GetRegistrationsAllKeys - List registrations for any key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetRegistrationsAllKeys(getRegistrationsAllKeysOptions *GetRegistrationsAllKeysOptions)`, func() {
			getRegistrationsAllKeysOptions := &ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID, XKmsKeyRing, UrlEncodedResourceCRNQuery,
				// PreventKeyDeletion, TotalCount — all set to "testString" in generated code.
			}

			registrationWithTotalCount, response, err := ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(registrationWithTotalCount).ToNot(BeNil())
		})
	})

	Describe(`CreateKeyAlias - Create an alias`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateKeyAlias(createKeyAliasOptions *CreateKeyAliasOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			createKeyAliasOptions := &ibmkeyprotectapiv2.CreateKeyAliasOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				Alias:           core.StringPtr("testAllias"), // MANUAL: alias value set to a valid name
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			keyAlias, response, err := ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptions)
			Expect(err).To(BeNil())
			// MANUAL: Fixed expected status code from 200 to 201 — the API returns 201 Created for alias creation.
			Expect(response.StatusCode).To(Equal(201))
			Expect(keyAlias).ToNot(BeNil())
		})
	})

	Describe(`DeleteKeyAlias - Delete an alias`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteKeyAlias(deleteKeyAliasOptions *DeleteKeyAliasOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			// MANUAL: Moved before PatchKey/DeleteKey so the alias is cleaned up while the key is still active.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			deleteKeyAliasOptions := &ibmkeyprotectapiv2.DeleteKeyAliasOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				Alias:           core.StringPtr("testAllias"), // MANUAL: must match alias created above
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			response, err := ibmKeyProtectApiService.DeleteKeyAlias(deleteKeyAliasOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`ListKeyRings - List key rings`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListKeyRings(listKeyRingsOptions *ListKeyRingsOptions)`, func() {
			listKeyRingsOptions := &ibmkeyprotectapiv2.ListKeyRingsOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				Limit:           core.Int64Ptr(int64(100)),
				Offset:          core.Int64Ptr(int64(0)),
				TotalCount:      core.BoolPtr(true),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			listKeyRingsWithTotalCount, response, err := ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKeyRingsWithTotalCount).ToNot(BeNil())
		})
	})

	Describe(`GetKmipAdapters - List KMIP Adapters`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKmipAdapters(getKmipAdaptersOptions *GetKmipAdaptersOptions)`, func() {
			getKmipAdaptersOptions := &ibmkeyprotectapiv2.GetKmipAdaptersOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID, Limit, Offset, TotalCount, and CrkID
				// (which had a hardcoded placeholder UUID). Listing adapters needs no filter.
			}

			listKmipAdaptersWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipAdaptersWithTotalCount).ToNot(BeNil())
		})
	})

	// MANUAL: Moved CreateKeyRing after GetKmipAdapters and before PatchKey/KMIP tests
	// so the ring exists when PatchKey moves the key into it.
	Describe(`CreateKeyRing - Create a key ring`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateKeyRing(createKeyRingOptions *CreateKeyRingOptions)`, func() {
			createKeyRingOptions := &ibmkeyprotectapiv2.CreateKeyRingOptions{
				KeyRingID:       core.StringPtr(createdKeyringID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			response, err := ibmKeyProtectApiService.CreateKeyRing(createKeyRingOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
		})
	})

	// MANUAL: Moved PatchKey after CreateKeyRing so the target ring already exists.
	// Also moved it before DeleteKey so the key is in the correct ring when deleted.
	Describe(`PatchKey - Update (patch) a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PatchKey(patchKeyOptions *PatchKeyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// MANUAL: Replaced CreateMockReader with a real JSON body that moves the key into the test ring.
			keyPatchBodyJSON, _ := json.Marshal(map[string]interface{}{"keyRingID": createdKeyringID})

			patchKeyOptions := &ibmkeyprotectapiv2.PatchKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				KeyPatchBody:    io.NopCloser(strings.NewReader(string(keyPatchBodyJSON))),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			patchKeyResponseBody, response, err := ibmKeyProtectApiService.PatchKey(patchKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(patchKeyResponseBody).ToNot(BeNil())
		})
	})

	Describe(`DeleteKey - Delete a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteKey(deleteKeyOptions *DeleteKeyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			fmt.Fprintf(GinkgoWriter, "Deleting Key ID: %s\n", createdKeyID)
			deleteKeyOptions := &ibmkeyprotectapiv2.DeleteKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				XKmsKeyRing:     core.StringPtr(createdKeyringID), // MANUAL: specify the ring the key lives in
				Prefer:          core.StringPtr("return=representation"),
				Force:           core.BoolPtr(false),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			deleteKey, response, err := ibmKeyProtectApiService.DeleteKey(deleteKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(deleteKey).ToNot(BeNil())
			// MANUAL: Record timestamp so RestoreKey can enforce the API's 30-second rate limit.
			deleteKeyTimestamp = time.Now()
		})
	})

	Describe(`RestoreKey - Restore a key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`RestoreKey(restoreKeyOptions *RestoreKeyOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to createdKeyID.
			// MANUAL: Moved RestoreKey to immediately after DeleteKey (was before DeleteKey in generated code).
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// MANUAL: Wait at least 31 seconds after DeleteKey to respect the API rate limit.
			// The generated code had no awareness of this constraint.
			if !deleteKeyTimestamp.IsZero() {
				elapsed := time.Since(deleteKeyTimestamp)
				if elapsed < 31*time.Second {
					fmt.Fprintf(GinkgoWriter, "Waiting %v for rate limit after DeleteKey\n", 31*time.Second-elapsed)
					time.Sleep(31*time.Second - elapsed)
				}
			}
			restoreKeyOptions := &ibmkeyprotectapiv2.RestoreKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				XKmsKeyRing:     core.StringPtr(createdKeyringID), // MANUAL: restore to the same ring
				Prefer:          core.StringPtr("return=representation"),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			result, response, err := ibmKeyProtectApiService.RestoreKey(restoreKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(result).ToNot(BeNil())
		})
	})

	// MANUAL: DeleteKeyRing expanded from a single API call into a two-step operation:
	// first patch the key back to the "default" ring (so the ring has no keys), then delete it.
	// Without this, DeleteKeyRing fails because the ring is non-empty.
	Describe(`DeleteKeyRing - Delete key ring`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteKeyRing(deleteKeyRingOptions *DeleteKeyRingOptions)`, func() {
			// MANUAL: Skip guard added.
			if createdKeyID == "" {
				Skip("No key ID available from CreateKey, skipping")
			}
			// MANUAL: First move the key back to the default ring so the ring becomes empty.
			keyPatchBodyJSON, _ := json.Marshal(map[string]interface{}{"keyRingID": "default"})
			patchOpts := &ibmkeyprotectapiv2.PatchKeyOptions{
				ID:              core.StringPtr(createdKeyID),
				BluemixInstance: core.StringPtr(bluemixInstance),
				XKmsKeyRing:     core.StringPtr(createdKeyringID), // MANUAL: must specify source ring
				KeyPatchBody:    io.NopCloser(strings.NewReader(string(keyPatchBodyJSON))),
			}
			patchResp, _, patchErr := ibmKeyProtectApiService.PatchKey(patchOpts)
			Expect(patchErr).To(BeNil())
			Expect(patchResp).ToNot(BeNil())

			deleteKeyRingOptions := &ibmkeyprotectapiv2.DeleteKeyRingOptions{
				KeyRingID:       core.StringPtr(createdKeyringID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				Force:           core.BoolPtr(false),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			response, err := ibmKeyProtectApiService.DeleteKeyRing(deleteKeyRingOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`PurgeKey - Purge a deleted key`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PurgeKey(purgeKeyOptions *PurgeKeyOptions)`, func() {
			// MANUAL: Skip added — PurgeKey requires the key to have been in the deleted state
			// for at least 4 hours. It cannot be run as part of a standard test suite run.
			Skip("Skipping PurgeKey — requires 4-hour wait after deletion")
			purgeKeyOptions := &ibmkeyprotectapiv2.PurgeKeyOptions{
				ID:              core.StringPtr(createdKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				XKmsKeyRing:     core.StringPtr(createdKeyringID),
				Prefer:          core.StringPtr("return=representation"),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			purgeKey, response, err := ibmKeyProtectApiService.PurgeKey(purgeKeyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(purgeKey).ToNot(BeNil())
		})
	})

	Describe(`SetKeyForDeletion - Set a key for deletion`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SetKeyForDeletion(setKeyForDeletionOptions *SetKeyForDeletionOptions)`, func() {
			// MANUAL: Skip added — requires dual-auth-delete policy to be enabled on the key.
			// Activating this in a test run would require a second actor to approve deletion
			// and would prevent cleanup from succeeding.
			Skip("Skipping SetKeyForDeletion — requires dual-auth policy, disruptive")
			if policiesOverriddenKeyID == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			setKeyForDeletionOptions := &ibmkeyprotectapiv2.SetKeyForDeletionOptions{
				ID:              core.StringPtr(policiesOverriddenKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			response, err := ibmKeyProtectApiService.SetKeyForDeletion(setKeyForDeletionOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`UnsetKeyForDeletion - Unset a key for deletion`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UnsetKeyForDeletion(unsetKeyForDeletionOptions *UnsetKeyForDeletionOptions)`, func() {
			// MANUAL: Skip added — same reason as SetKeyForDeletion above.
			Skip("Skipping UnsetKeyForDeletion — requires dual-auth policy, disruptive")
			if policiesOverriddenKeyID == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			unsetKeyForDeletionOptions := &ibmkeyprotectapiv2.UnsetKeyForDeletionOptions{
				ID:              core.StringPtr(policiesOverriddenKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			response, err := ibmKeyProtectApiService.UnsetKeyForDeletion(unsetKeyForDeletionOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`SyncAssociatedResources - Sync associated resources`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SyncAssociatedResources(syncAssociatedResourcesOptions *SyncAssociatedResourcesOptions)`, func() {
			// MANUAL: Skip guard added; ID changed from "testString" to policiesOverriddenKeyID
			// to match the Python test which syncs the policies-overridden key, not the standard one.
			if policiesOverriddenKeyID == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			syncAssociatedResourcesOptions := &ibmkeyprotectapiv2.SyncAssociatedResourcesOptions{
				ID:              core.StringPtr(policiesOverriddenKeyID), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID and XKmsKeyRing set to "testString".
			}

			response, err := ibmKeyProtectApiService.SyncAssociatedResources(syncAssociatedResourcesOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`CreateKmipAdapter - Create a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateKmipAdapter(createKmipAdapterOptions *CreateKmipAdapterOptions)`, func() {
			// MANUAL: Skip guard added — KMIP adapter needs a real CRK ID.
			if policiesOverriddenKeyID == "" {
				Skip("No key ID available from CreateKeyWithPoliciesOverrides, skipping")
			}
			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			kmipProfileDataBodyModel := &ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative{
				// MANUAL: Changed from hardcoded placeholder UUID "feddecaf-0000-0000-0000-1234567890ab"
				// to the actual policiesOverriddenKeyID created earlier in the test run.
				CrkID: core.StringPtr(policiesOverriddenKeyID),
			}

			createKmipAdapterObjectModel := &ibmkeyprotectapiv2.CreateKMIPAdapterObject{
				Name:        core.StringPtr(kmipName), // MANUAL: was "kmip-adapter-name"
				Description: core.StringPtr("Test KMIP adapter created by integration test"),
				Profile:     core.StringPtr("native_1.0"),
				ProfileData: kmipProfileDataBodyModel,
			}

			createKmipAdapterOptions := &ibmkeyprotectapiv2.CreateKmipAdapterOptions{
				BluemixInstance: core.StringPtr(bluemixInstance),
				Metadata:        collectionMetadataModel,
				Resources:       []ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel},
				// MANUAL: Removed CorrelationID and AllowExpiringKey set to "testString"/true.
			}

			listKmipAdapters, response, err := ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(listKmipAdapters).ToNot(BeNil())
		})
	})

	Describe(`GetKmipAdapter - Retrieve a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKmipAdapter(getKmipAdapterOptions *GetKmipAdapterOptions)`, func() {
			getKmipAdapterOptions := &ibmkeyprotectapiv2.GetKmipAdapterOptions{
				ID:              core.StringPtr(kmipName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			listKmipAdapters, response, err := ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipAdapters).ToNot(BeNil())
		})
	})

	Describe(`GetKmipObjects - List KMIP objects of a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKmipObjects(getKmipObjectsOptions *GetKmipObjectsOptions)`, func() {
			getKmipObjectsOptions := &ibmkeyprotectapiv2.GetKmipObjectsOptions{
				AdapterID:       core.StringPtr(kmipName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed Limit, Offset, TotalCount, State, CorrelationID
				// — generated code set State to []int64{1,2,3,4} and others to "testString".
			}

			listKmipObjectsWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipObjectsWithTotalCount).ToNot(BeNil())
		})
	})

	Describe(`GetKmipObject - Retrieve a KMIP object from a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKmipObject(getKmipObjectOptions *GetKmipObjectOptions)`, func() {
			// MANUAL: Skip added — no KMIP object is created during the test run so this
			// would always 404. A real object ID would be needed to test this.
			Skip("Skipping GetKmipObject — no KMIP object created during test run")
			getKmipObjectOptions := &ibmkeyprotectapiv2.GetKmipObjectOptions{
				AdapterID:       core.StringPtr(kmipName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				ID:              core.StringPtr("testString"), // placeholder — test is skipped
				// MANUAL: Removed CorrelationID set to "testString".
			}

			listKmipObjectsWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipObjectsWithTotalCount).ToNot(BeNil())
		})
	})

	Describe(`GetKmipClientCertificates - List client certificates of a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKmipClientCertificates(getKmipClientCertificatesOptions *GetKmipClientCertificatesOptions)`, func() {
			getKmipClientCertificatesOptions := &ibmkeyprotectapiv2.GetKmipClientCertificatesOptions{
				AdapterID:       core.StringPtr(kmipName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed Limit, Offset, TotalCount, CorrelationID set to "testString".
			}

			listKmipPartialClientCertificatesWithTotalCount, response, err := ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipPartialClientCertificatesWithTotalCount).ToNot(BeNil())
		})
	})

	Describe(`AddKmipClientCertificate - Add a client certificate to a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`AddKmipClientCertificate(addKmipClientCertificateOptions *AddKmipClientCertificateOptions)`, func() {
			collectionMetadataModel := &ibmkeyprotectapiv2.CollectionMetadata{
				CollectionType:  core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json"),
				CollectionTotal: core.Int64Ptr(int64(1)),
			}

			createKmipClientCertificateObjectModel := &ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{
				Certificate: core.StringPtr(generateTestCertPEM()), // MANUAL: generated in-process
				Name:        core.StringPtr(kmipCertName),          // MANUAL: was "testString"
			}

			addKmipClientCertificateOptions := &ibmkeyprotectapiv2.AddKmipClientCertificateOptions{
				AdapterID:       core.StringPtr(kmipName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				Metadata:        collectionMetadataModel,
				Resources:       []ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel},
				// MANUAL: Removed CorrelationID set to "testString".
			}

			listKmipClientCertificates, response, err := ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(listKmipClientCertificates).ToNot(BeNil())
		})
	})

	Describe(`GetKmipClientCertificate - Retrieve a client certificate from a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetKmipClientCertificate(getKmipClientCertificateOptions *GetKmipClientCertificateOptions)`, func() {
			getKmipClientCertificateOptions := &ibmkeyprotectapiv2.GetKmipClientCertificateOptions{
				AdapterID:       core.StringPtr(kmipName),     // MANUAL: was "testString"
				ID:              core.StringPtr(kmipCertName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			listKmipClientCertificates, response, err := ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(listKmipClientCertificates).ToNot(BeNil())
		})
	})

	Describe(`DeleteKmipClientCertificate - Delete a client certificate from a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteKmipClientCertificate(deleteKmipClientCertificateOptions *DeleteKmipClientCertificateOptions)`, func() {
			deleteKmipClientCertificateOptions := &ibmkeyprotectapiv2.DeleteKmipClientCertificateOptions{
				AdapterID:       core.StringPtr(kmipName),     // MANUAL: was "testString"
				ID:              core.StringPtr(kmipCertName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			response, err := ibmKeyProtectApiService.DeleteKmipClientCertificate(deleteKmipClientCertificateOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteKmipAdapter - Delete a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteKmipAdapter(deleteKmipAdapterOptions *DeleteKmipAdapterOptions)`, func() {
			deleteKmipAdapterOptions := &ibmkeyprotectapiv2.DeleteKmipAdapterOptions{
				ID:              core.StringPtr(kmipName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			response, err := ibmKeyProtectApiService.DeleteKmipAdapter(deleteKmipAdapterOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteKmipObject - Delete a KMIP object from a KMIP Adapter`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteKmipObject(deleteKmipObjectOptions *DeleteKmipObjectOptions)`, func() {
			// MANUAL: Skip added — no KMIP object is created during the test run.
			Skip("Skipping DeleteKmipObject — no KMIP object created during test run")
			deleteKmipObjectOptions := &ibmkeyprotectapiv2.DeleteKmipObjectOptions{
				AdapterID:       core.StringPtr(kmipName), // MANUAL: was "testString"
				BluemixInstance: core.StringPtr(bluemixInstance),
				ID:              core.StringPtr("testString"), // placeholder — test is skipped
				Force:           core.BoolPtr(false),
				// MANUAL: Removed CorrelationID set to "testString".
			}

			response, err := ibmKeyProtectApiService.DeleteKmipObject(deleteKmipObjectOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	// MANUAL: Added the entire Cleanup Describe block. The generated file had no cleanup.
	// This runs after all tests and best-effort deletes all resources so the instance is left clean.
	// Failures here are logged but do not fail the suite.
	Describe(`Cleanup - Remove all resources created during integration tests`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})

		It(`Best-effort cleanup of created key`, func() {
			if createdKeyID == "" {
				Skip("No created key ID available, skipping cleanup")
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: deleting created key %s\n", createdKeyID)
			deleteOpts := &ibmkeyprotectapiv2.DeleteKeyOptions{
				ID:              core.StringPtr(createdKeyID),
				BluemixInstance: core.StringPtr(bluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
			}
			_, _, deleteErr := ibmKeyProtectApiService.DeleteKey(deleteOpts)
			if deleteErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: delete created key failed (may already be deleted): %v\n", deleteErr)
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: purging created key %s\n", createdKeyID)
			purgeOpts := &ibmkeyprotectapiv2.PurgeKeyOptions{
				ID:              core.StringPtr(createdKeyID),
				BluemixInstance: core.StringPtr(bluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
			}
			_, _, purgeErr := ibmKeyProtectApiService.PurgeKey(purgeOpts)
			if purgeErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: purge created key failed (may need 4-hour wait): %v\n", purgeErr)
			}
		})

		It(`Best-effort cleanup of policies-overridden key`, func() {
			if policiesOverriddenKeyID == "" {
				Skip("No policies-overridden key ID available, skipping cleanup")
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: deleting policies-overridden key %s\n", policiesOverriddenKeyID)
			deleteOpts := &ibmkeyprotectapiv2.DeleteKeyOptions{
				ID:              core.StringPtr(policiesOverriddenKeyID),
				BluemixInstance: core.StringPtr(bluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
				Force:           core.BoolPtr(false),
			}
			_, _, deleteErr := ibmKeyProtectApiService.DeleteKey(deleteOpts)
			if deleteErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: delete policies-overridden key failed (may already be deleted): %v\n", deleteErr)
			}

			fmt.Fprintf(GinkgoWriter, "Cleanup: purging policies-overridden key %s\n", policiesOverriddenKeyID)
			purgeOpts := &ibmkeyprotectapiv2.PurgeKeyOptions{
				ID:              core.StringPtr(policiesOverriddenKeyID),
				BluemixInstance: core.StringPtr(bluemixInstance),
				Prefer:          core.StringPtr("return=representation"),
			}
			_, _, purgeErr := ibmKeyProtectApiService.PurgeKey(purgeOpts)
			if purgeErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: purge policies-overridden key failed (may need 4-hour wait): %v\n", purgeErr)
			}
		})

		It(`Best-effort cleanup of key ring`, func() {
			fmt.Fprintf(GinkgoWriter, "Cleanup: deleting key ring %s\n", createdKeyringID)
			deleteRingOpts := &ibmkeyprotectapiv2.DeleteKeyRingOptions{
				KeyRingID:       core.StringPtr(createdKeyringID),
				BluemixInstance: core.StringPtr(bluemixInstance),
				Force:           core.BoolPtr(false),
			}
			_, ringErr := ibmKeyProtectApiService.DeleteKeyRing(deleteRingOpts)
			if ringErr != nil {
				fmt.Fprintf(GinkgoWriter, "Cleanup: delete key ring failed (may already be deleted): %v\n", ringErr)
			}
		})
	})
})

//
// Utility functions are declared in the unit test file
//
