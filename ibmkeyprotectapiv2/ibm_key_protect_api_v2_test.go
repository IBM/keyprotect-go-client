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

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`IbmKeyProtectApiV2`, func() {
	var testServer *httptest.Server
	Describe(`Service constructor tests`, func() {
		It(`Instantiate service client`, func() {
			ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
				Authenticator: &core.NoAuthAuthenticator{},
			})
			Expect(ibmKeyProtectApiService).ToNot(BeNil())
			Expect(serviceErr).To(BeNil())
		})
		It(`Instantiate service client with error: Invalid URL`, func() {
			ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
				URL: "{BAD_URL_STRING",
			})
			Expect(ibmKeyProtectApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
		It(`Instantiate service client with error: Invalid Auth`, func() {
			ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
				URL: "https://ibmkeyprotectapiv2/api",
				Authenticator: &core.BasicAuthenticator{
					Username: "",
					Password: "",
				},
			})
			Expect(ibmKeyProtectApiService).To(BeNil())
			Expect(serviceErr).ToNot(BeNil())
		})
	})
	Describe(`Service constructor tests using external config`, func() {
		Context(`Using external config, construct service client instances`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_KEY_PROTECT_API_URL":       "https://ibmkeyprotectapiv2/api",
				"IBM_KEY_PROTECT_API_AUTH_TYPE": "noauth",
			}

			It(`Create service client using external config successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2UsingExternalConfig(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{})
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				ClearTestEnvironment(testEnvironment)

				clone := ibmKeyProtectApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmKeyProtectApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmKeyProtectApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmKeyProtectApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url from constructor successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2UsingExternalConfig(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL: "https://testService/api",
				})
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmKeyProtectApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmKeyProtectApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmKeyProtectApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmKeyProtectApiService.Service.Options.Authenticator))
			})
			It(`Create service client using external config and set url programatically successfully`, func() {
				SetTestEnvironment(testEnvironment)
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2UsingExternalConfig(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{})
				err := ibmKeyProtectApiService.SetServiceURL("https://testService/api")
				Expect(err).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService.Service.GetServiceURL()).To(Equal("https://testService/api"))
				ClearTestEnvironment(testEnvironment)

				clone := ibmKeyProtectApiService.Clone()
				Expect(clone).ToNot(BeNil())
				Expect(clone.Service != ibmKeyProtectApiService.Service).To(BeTrue())
				Expect(clone.GetServiceURL()).To(Equal(ibmKeyProtectApiService.GetServiceURL()))
				Expect(clone.Service.Options.Authenticator).To(Equal(ibmKeyProtectApiService.Service.Options.Authenticator))
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid Auth`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_KEY_PROTECT_API_URL":       "https://ibmkeyprotectapiv2/api",
				"IBM_KEY_PROTECT_API_AUTH_TYPE": "someOtherAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2UsingExternalConfig(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{})

			It(`Instantiate service client with error`, func() {
				Expect(ibmKeyProtectApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
		Context(`Using external config, construct service client instances with error: Invalid URL`, func() {
			// Map containing environment variables used in testing.
			var testEnvironment = map[string]string{
				"IBM_KEY_PROTECT_API_AUTH_TYPE": "NOAuth",
			}

			SetTestEnvironment(testEnvironment)
			ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2UsingExternalConfig(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
				URL: "{BAD_URL_STRING",
			})

			It(`Instantiate service client with error`, func() {
				Expect(ibmKeyProtectApiService).To(BeNil())
				Expect(serviceErr).ToNot(BeNil())
				ClearTestEnvironment(testEnvironment)
			})
		})
	})
	Describe(`Regional endpoint tests`, func() {
		It(`GetServiceURLForRegion(region string)`, func() {
			var url string
			var err error
			url, err = ibmkeyprotectapiv2.GetServiceURLForRegion("INVALID_REGION")
			Expect(url).To(BeEmpty())
			Expect(err).ToNot(BeNil())
			fmt.Fprintf(GinkgoWriter, "Expected error: %s\n", err.Error())
		})
	})
	Describe(`Parameterized URL tests`, func() {
		It(`Format parameterized URL with all default values`, func() {
			constructedURL, err := ibmkeyprotectapiv2.ConstructServiceURL(nil)
			Expect(constructedURL).To(Equal("https://us-south.kms.cloud.ibm.com"))
			Expect(constructedURL).ToNot(BeNil())
			Expect(err).To(BeNil())
		})
		It(`Return an error if a provided variable name is invalid`, func() {
			var providedUrlVariables = map[string]string{
				"invalid_variable_name": "value",
			}
			constructedURL, err := ibmkeyprotectapiv2.ConstructServiceURL(providedUrlVariables)
			Expect(constructedURL).To(Equal(""))
			Expect(err).ToNot(BeNil())
		})
	})
	Describe(`GetKeyCollectionMetadata(getKeyCollectionMetadataOptions *GetKeyCollectionMetadataOptions)`, func() {
		getKeyCollectionMetadataPath := "/api/v2/keys"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyCollectionMetadataPath))
					Expect(req.Method).To(Equal("HEAD"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// TODO: Add check for extractable query parameter
					Expect(req.URL.Query()["filter"]).To(Equal([]string{"testString"}))
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKeyCollectionMetadata successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.GetKeyCollectionMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the GetKeyCollectionMetadataOptions model
				getKeyCollectionMetadataOptionsModel := new(ibmkeyprotectapiv2.GetKeyCollectionMetadataOptions)
				getKeyCollectionMetadataOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.State = []int64{0, 1, 2, 3}
				getKeyCollectionMetadataOptionsModel.Extractable = core.BoolPtr(true)
				getKeyCollectionMetadataOptionsModel.Filter = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.GetKeyCollectionMetadata(getKeyCollectionMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke GetKeyCollectionMetadata with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyCollectionMetadataOptions model
				getKeyCollectionMetadataOptionsModel := new(ibmkeyprotectapiv2.GetKeyCollectionMetadataOptions)
				getKeyCollectionMetadataOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.State = []int64{0, 1, 2, 3}
				getKeyCollectionMetadataOptionsModel.Extractable = core.BoolPtr(true)
				getKeyCollectionMetadataOptionsModel.Filter = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyCollectionMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.GetKeyCollectionMetadata(getKeyCollectionMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the GetKeyCollectionMetadataOptions model with no property values
				getKeyCollectionMetadataOptionsModelNew := new(ibmkeyprotectapiv2.GetKeyCollectionMetadataOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.GetKeyCollectionMetadata(getKeyCollectionMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKey(createKeyOptions *CreateKeyOptions) - Operation response error`, func() {
		createKeyPath := "/api/v2/keys"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyOptions model
				createKeyOptionsModel := new(ibmkeyprotectapiv2.CreateKeyOptions)
				createKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyOptionsModel.KeyCreateBody = CreateMockReader("This is a mock file.")
				createKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.CreateKey(createKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.CreateKey(createKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKey(createKeyOptions *CreateKeyOptions)`, func() {
		createKeyPath := "/api/v2/keys"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke CreateKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the CreateKeyOptions model
				createKeyOptionsModel := new(ibmkeyprotectapiv2.CreateKeyOptions)
				createKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyOptionsModel.KeyCreateBody = CreateMockReader("This is a mock file.")
				createKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.CreateKeyWithContext(ctx, createKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.CreateKey(createKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.CreateKeyWithContext(ctx, createKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke CreateKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.CreateKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CreateKeyOptions model
				createKeyOptionsModel := new(ibmkeyprotectapiv2.CreateKeyOptions)
				createKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyOptionsModel.KeyCreateBody = CreateMockReader("This is a mock file.")
				createKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKey(createKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyOptions model
				createKeyOptionsModel := new(ibmkeyprotectapiv2.CreateKeyOptions)
				createKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyOptionsModel.KeyCreateBody = CreateMockReader("This is a mock file.")
				createKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.CreateKey(createKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateKeyOptions model with no property values
				createKeyOptionsModelNew := new(ibmkeyprotectapiv2.CreateKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKey(createKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyOptions model
				createKeyOptionsModel := new(ibmkeyprotectapiv2.CreateKeyOptions)
				createKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyOptionsModel.KeyCreateBody = CreateMockReader("This is a mock file.")
				createKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.CreateKey(createKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKeys(getKeysOptions *GetKeysOptions) - Operation response error`, func() {
		getKeysPath := "/api/v2/keys"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeysPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for extractable query parameter
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"id"}))
					Expect(req.URL.Query()["filter"]).To(Equal([]string{"testString"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKeys with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeysOptions model
				getKeysOptionsModel := new(ibmkeyprotectapiv2.GetKeysOptions)
				getKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeysOptionsModel.State = []int64{0, 1, 2, 3}
				getKeysOptionsModel.Extractable = core.BoolPtr(true)
				getKeysOptionsModel.Search = core.StringPtr("testString")
				getKeysOptionsModel.Sort = core.StringPtr("id")
				getKeysOptionsModel.Filter = core.StringPtr("testString")
				getKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKeys(getKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKeys(getKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKeys(getKeysOptions *GetKeysOptions)`, func() {
		getKeysPath := "/api/v2/keys"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeysPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for extractable query parameter
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"id"}))
					Expect(req.URL.Query()["filter"]).To(Equal([]string{"testString"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "incompleteSearch": true, "searchQuery": {"query": "Query", "scopes": ["name"], "not": false, "exact": false}}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetKeys successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKeysOptions model
				getKeysOptionsModel := new(ibmkeyprotectapiv2.GetKeysOptions)
				getKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeysOptionsModel.State = []int64{0, 1, 2, 3}
				getKeysOptionsModel.Extractable = core.BoolPtr(true)
				getKeysOptionsModel.Search = core.StringPtr("testString")
				getKeysOptionsModel.Sort = core.StringPtr("id")
				getKeysOptionsModel.Filter = core.StringPtr("testString")
				getKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKeysWithContext(ctx, getKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKeys(getKeysOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKeysWithContext(ctx, getKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeysPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for extractable query parameter
					Expect(req.URL.Query()["search"]).To(Equal([]string{"testString"}))
					Expect(req.URL.Query()["sort"]).To(Equal([]string{"id"}))
					Expect(req.URL.Query()["filter"]).To(Equal([]string{"testString"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "incompleteSearch": true, "searchQuery": {"query": "Query", "scopes": ["name"], "not": false, "exact": false}}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetKeys successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKeys(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKeysOptions model
				getKeysOptionsModel := new(ibmkeyprotectapiv2.GetKeysOptions)
				getKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeysOptionsModel.State = []int64{0, 1, 2, 3}
				getKeysOptionsModel.Extractable = core.BoolPtr(true)
				getKeysOptionsModel.Search = core.StringPtr("testString")
				getKeysOptionsModel.Sort = core.StringPtr("id")
				getKeysOptionsModel.Filter = core.StringPtr("testString")
				getKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKeys(getKeysOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKeys with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeysOptions model
				getKeysOptionsModel := new(ibmkeyprotectapiv2.GetKeysOptions)
				getKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeysOptionsModel.State = []int64{0, 1, 2, 3}
				getKeysOptionsModel.Extractable = core.BoolPtr(true)
				getKeysOptionsModel.Search = core.StringPtr("testString")
				getKeysOptionsModel.Sort = core.StringPtr("id")
				getKeysOptionsModel.Filter = core.StringPtr("testString")
				getKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKeys(getKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKeysOptions model with no property values
				getKeysOptionsModelNew := new(ibmkeyprotectapiv2.GetKeysOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKeys(getKeysOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKeys successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeysOptions model
				getKeysOptionsModel := new(ibmkeyprotectapiv2.GetKeysOptions)
				getKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeysOptionsModel.State = []int64{0, 1, 2, 3}
				getKeysOptionsModel.Extractable = core.BoolPtr(true)
				getKeysOptionsModel.Search = core.StringPtr("testString")
				getKeysOptionsModel.Sort = core.StringPtr("id")
				getKeysOptionsModel.Filter = core.StringPtr("testString")
				getKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKeys(getKeysOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptions *CreateKeyWithPoliciesOverridesOptions) - Operation response error`, func() {
		createKeyWithPoliciesOverridesPath := "/api/v2/keys_with_policy_overrides"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyWithPoliciesOverridesPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateKeyWithPoliciesOverrides with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyWithPoliciesOverridesOptions model
				createKeyWithPoliciesOverridesOptionsModel := new(ibmkeyprotectapiv2.CreateKeyWithPoliciesOverridesOptions)
				createKeyWithPoliciesOverridesOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.KeyWithPolicyOverridesCreateBody = CreateMockReader("This is a mock file.")
				createKeyWithPoliciesOverridesOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyWithPoliciesOverridesOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyWithPoliciesOverridesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptions *CreateKeyWithPoliciesOverridesOptions)`, func() {
		createKeyWithPoliciesOverridesPath := "/api/v2/keys_with_policy_overrides"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyWithPoliciesOverridesPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke CreateKeyWithPoliciesOverrides successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the CreateKeyWithPoliciesOverridesOptions model
				createKeyWithPoliciesOverridesOptionsModel := new(ibmkeyprotectapiv2.CreateKeyWithPoliciesOverridesOptions)
				createKeyWithPoliciesOverridesOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.KeyWithPolicyOverridesCreateBody = CreateMockReader("This is a mock file.")
				createKeyWithPoliciesOverridesOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyWithPoliciesOverridesOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyWithPoliciesOverridesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.CreateKeyWithPoliciesOverridesWithContext(ctx, createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.CreateKeyWithPoliciesOverridesWithContext(ctx, createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyWithPoliciesOverridesPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke CreateKeyWithPoliciesOverrides successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CreateKeyWithPoliciesOverridesOptions model
				createKeyWithPoliciesOverridesOptionsModel := new(ibmkeyprotectapiv2.CreateKeyWithPoliciesOverridesOptions)
				createKeyWithPoliciesOverridesOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.KeyWithPolicyOverridesCreateBody = CreateMockReader("This is a mock file.")
				createKeyWithPoliciesOverridesOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyWithPoliciesOverridesOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyWithPoliciesOverridesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateKeyWithPoliciesOverrides with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyWithPoliciesOverridesOptions model
				createKeyWithPoliciesOverridesOptionsModel := new(ibmkeyprotectapiv2.CreateKeyWithPoliciesOverridesOptions)
				createKeyWithPoliciesOverridesOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.KeyWithPolicyOverridesCreateBody = CreateMockReader("This is a mock file.")
				createKeyWithPoliciesOverridesOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyWithPoliciesOverridesOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyWithPoliciesOverridesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateKeyWithPoliciesOverridesOptions model with no property values
				createKeyWithPoliciesOverridesOptionsModelNew := new(ibmkeyprotectapiv2.CreateKeyWithPoliciesOverridesOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateKeyWithPoliciesOverrides successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyWithPoliciesOverridesOptions model
				createKeyWithPoliciesOverridesOptionsModel := new(ibmkeyprotectapiv2.CreateKeyWithPoliciesOverridesOptions)
				createKeyWithPoliciesOverridesOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.KeyWithPolicyOverridesCreateBody = CreateMockReader("This is a mock file.")
				createKeyWithPoliciesOverridesOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyWithPoliciesOverridesOptionsModel.Prefer = core.StringPtr("return=representation")
				createKeyWithPoliciesOverridesOptionsModel.XKmsKeyRing = core.StringPtr("default")
				createKeyWithPoliciesOverridesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKey(getKeyOptions *GetKeyOptions) - Operation response error`, func() {
		getKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyOptions model
				getKeyOptionsModel := new(ibmkeyprotectapiv2.GetKeyOptions)
				getKeyOptionsModel.ID = core.StringPtr("testString")
				getKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKey(getKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKey(getKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKey(getKeyOptions *GetKeyOptions)`, func() {
		getKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke GetKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKeyOptions model
				getKeyOptionsModel := new(ibmkeyprotectapiv2.GetKeyOptions)
				getKeyOptionsModel.ID = core.StringPtr("testString")
				getKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKeyWithContext(ctx, getKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKey(getKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKeyWithContext(ctx, getKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke GetKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKeyOptions model
				getKeyOptionsModel := new(ibmkeyprotectapiv2.GetKeyOptions)
				getKeyOptionsModel.ID = core.StringPtr("testString")
				getKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKey(getKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyOptions model
				getKeyOptionsModel := new(ibmkeyprotectapiv2.GetKeyOptions)
				getKeyOptionsModel.ID = core.StringPtr("testString")
				getKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKey(getKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKeyOptions model with no property values
				getKeyOptionsModelNew := new(ibmkeyprotectapiv2.GetKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKey(getKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyOptions model
				getKeyOptionsModel := new(ibmkeyprotectapiv2.GetKeyOptions)
				getKeyOptionsModel.ID = core.StringPtr("testString")
				getKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKey(getKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ActionOnKey(actionOnKeyOptions *ActionOnKeyOptions) - Operation response error`, func() {
		actionOnKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(actionOnKeyPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.URL.Query()["action"]).To(Equal([]string{"disable"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ActionOnKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the ActionOnKeyOptions model
				actionOnKeyOptionsModel := new(ibmkeyprotectapiv2.ActionOnKeyOptions)
				actionOnKeyOptionsModel.ID = core.StringPtr("testString")
				actionOnKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				actionOnKeyOptionsModel.Action = core.StringPtr("disable")
				actionOnKeyOptionsModel.KeyActionBody = CreateMockReader("This is a mock file.")
				actionOnKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				actionOnKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				actionOnKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				actionOnKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.ActionOnKey(actionOnKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.ActionOnKey(actionOnKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ActionOnKey(actionOnKeyOptions *ActionOnKeyOptions)`, func() {
		actionOnKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(actionOnKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.URL.Query()["action"]).To(Equal([]string{"disable"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"plaintext": "Plaintext", "ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke ActionOnKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the ActionOnKeyOptions model
				actionOnKeyOptionsModel := new(ibmkeyprotectapiv2.ActionOnKeyOptions)
				actionOnKeyOptionsModel.ID = core.StringPtr("testString")
				actionOnKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				actionOnKeyOptionsModel.Action = core.StringPtr("disable")
				actionOnKeyOptionsModel.KeyActionBody = CreateMockReader("This is a mock file.")
				actionOnKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				actionOnKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				actionOnKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				actionOnKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.ActionOnKeyWithContext(ctx, actionOnKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.ActionOnKey(actionOnKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.ActionOnKeyWithContext(ctx, actionOnKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(actionOnKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					Expect(req.URL.Query()["action"]).To(Equal([]string{"disable"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"plaintext": "Plaintext", "ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke ActionOnKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.ActionOnKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ActionOnKeyOptions model
				actionOnKeyOptionsModel := new(ibmkeyprotectapiv2.ActionOnKeyOptions)
				actionOnKeyOptionsModel.ID = core.StringPtr("testString")
				actionOnKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				actionOnKeyOptionsModel.Action = core.StringPtr("disable")
				actionOnKeyOptionsModel.KeyActionBody = CreateMockReader("This is a mock file.")
				actionOnKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				actionOnKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				actionOnKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				actionOnKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.ActionOnKey(actionOnKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ActionOnKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the ActionOnKeyOptions model
				actionOnKeyOptionsModel := new(ibmkeyprotectapiv2.ActionOnKeyOptions)
				actionOnKeyOptionsModel.ID = core.StringPtr("testString")
				actionOnKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				actionOnKeyOptionsModel.Action = core.StringPtr("disable")
				actionOnKeyOptionsModel.KeyActionBody = CreateMockReader("This is a mock file.")
				actionOnKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				actionOnKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				actionOnKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				actionOnKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.ActionOnKey(actionOnKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ActionOnKeyOptions model with no property values
				actionOnKeyOptionsModelNew := new(ibmkeyprotectapiv2.ActionOnKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.ActionOnKey(actionOnKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ActionOnKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the ActionOnKeyOptions model
				actionOnKeyOptionsModel := new(ibmkeyprotectapiv2.ActionOnKeyOptions)
				actionOnKeyOptionsModel.ID = core.StringPtr("testString")
				actionOnKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				actionOnKeyOptionsModel.Action = core.StringPtr("disable")
				actionOnKeyOptionsModel.KeyActionBody = CreateMockReader("This is a mock file.")
				actionOnKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				actionOnKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				actionOnKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				actionOnKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.ActionOnKey(actionOnKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PatchKey(patchKeyOptions *PatchKeyOptions) - Operation response error`, func() {
		patchKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(patchKeyPath))
					Expect(req.Method).To(Equal("PATCH"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PatchKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PatchKeyOptions model
				patchKeyOptionsModel := new(ibmkeyprotectapiv2.PatchKeyOptions)
				patchKeyOptionsModel.ID = core.StringPtr("testString")
				patchKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				patchKeyOptionsModel.KeyPatchBody = CreateMockReader("This is a mock file.")
				patchKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				patchKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				patchKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.PatchKey(patchKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.PatchKey(patchKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PatchKey(patchKeyOptions *PatchKeyOptions)`, func() {
		patchKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(patchKeyPath))
					Expect(req.Method).To(Equal("PATCH"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke PatchKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the PatchKeyOptions model
				patchKeyOptionsModel := new(ibmkeyprotectapiv2.PatchKeyOptions)
				patchKeyOptionsModel.ID = core.StringPtr("testString")
				patchKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				patchKeyOptionsModel.KeyPatchBody = CreateMockReader("This is a mock file.")
				patchKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				patchKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				patchKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.PatchKeyWithContext(ctx, patchKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.PatchKey(patchKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.PatchKeyWithContext(ctx, patchKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(patchKeyPath))
					Expect(req.Method).To(Equal("PATCH"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke PatchKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.PatchKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PatchKeyOptions model
				patchKeyOptionsModel := new(ibmkeyprotectapiv2.PatchKeyOptions)
				patchKeyOptionsModel.ID = core.StringPtr("testString")
				patchKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				patchKeyOptionsModel.KeyPatchBody = CreateMockReader("This is a mock file.")
				patchKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				patchKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				patchKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.PatchKey(patchKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PatchKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PatchKeyOptions model
				patchKeyOptionsModel := new(ibmkeyprotectapiv2.PatchKeyOptions)
				patchKeyOptionsModel.ID = core.StringPtr("testString")
				patchKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				patchKeyOptionsModel.KeyPatchBody = CreateMockReader("This is a mock file.")
				patchKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				patchKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				patchKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.PatchKey(patchKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PatchKeyOptions model with no property values
				patchKeyOptionsModelNew := new(ibmkeyprotectapiv2.PatchKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.PatchKey(patchKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke PatchKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PatchKeyOptions model
				patchKeyOptionsModel := new(ibmkeyprotectapiv2.PatchKeyOptions)
				patchKeyOptionsModel.ID = core.StringPtr("testString")
				patchKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				patchKeyOptionsModel.KeyPatchBody = CreateMockReader("This is a mock file.")
				patchKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				patchKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				patchKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.PatchKey(patchKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteKey(deleteKeyOptions *DeleteKeyOptions) - Operation response error`, func() {
		deleteKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKeyPath))
					Expect(req.Method).To(Equal("DELETE"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					// TODO: Add check for force query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke DeleteKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKeyOptions model
				deleteKeyOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyOptions)
				deleteKeyOptionsModel.ID = core.StringPtr("testString")
				deleteKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				deleteKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				deleteKeyOptionsModel.Force = core.BoolPtr(false)
				deleteKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.DeleteKey(deleteKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.DeleteKey(deleteKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteKey(deleteKeyOptions *DeleteKeyOptions)`, func() {
		deleteKeyPath := "/api/v2/keys/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKeyPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					// TODO: Add check for force query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke DeleteKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the DeleteKeyOptions model
				deleteKeyOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyOptions)
				deleteKeyOptionsModel.ID = core.StringPtr("testString")
				deleteKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				deleteKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				deleteKeyOptionsModel.Force = core.BoolPtr(false)
				deleteKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.DeleteKeyWithContext(ctx, deleteKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.DeleteKey(deleteKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.DeleteKeyWithContext(ctx, deleteKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKeyPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					// TODO: Add check for force query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z", "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}]}`)
				}))
			})
			It(`Invoke DeleteKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.DeleteKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the DeleteKeyOptions model
				deleteKeyOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyOptions)
				deleteKeyOptionsModel.ID = core.StringPtr("testString")
				deleteKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				deleteKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				deleteKeyOptionsModel.Force = core.BoolPtr(false)
				deleteKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.DeleteKey(deleteKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke DeleteKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKeyOptions model
				deleteKeyOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyOptions)
				deleteKeyOptionsModel.ID = core.StringPtr("testString")
				deleteKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				deleteKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				deleteKeyOptionsModel.Force = core.BoolPtr(false)
				deleteKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.DeleteKey(deleteKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the DeleteKeyOptions model with no property values
				deleteKeyOptionsModelNew := new(ibmkeyprotectapiv2.DeleteKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.DeleteKey(deleteKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke DeleteKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKeyOptions model
				deleteKeyOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyOptions)
				deleteKeyOptionsModel.ID = core.StringPtr("testString")
				deleteKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				deleteKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				deleteKeyOptionsModel.Force = core.BoolPtr(false)
				deleteKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.DeleteKey(deleteKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKeyMetadata(getKeyMetadataOptions *GetKeyMetadataOptions) - Operation response error`, func() {
		getKeyMetadataPath := "/api/v2/keys/testString/metadata"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyMetadataPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKeyMetadata with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyMetadataOptions model
				getKeyMetadataOptionsModel := new(ibmkeyprotectapiv2.GetKeyMetadataOptions)
				getKeyMetadataOptionsModel.ID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyMetadataOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKeyMetadata(getKeyMetadataOptions *GetKeyMetadataOptions)`, func() {
		getKeyMetadataPath := "/api/v2/keys/testString/metadata"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyMetadataPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetKeyMetadata successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKeyMetadataOptions model
				getKeyMetadataOptionsModel := new(ibmkeyprotectapiv2.GetKeyMetadataOptions)
				getKeyMetadataOptionsModel.ID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyMetadataOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKeyMetadataWithContext(ctx, getKeyMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKeyMetadataWithContext(ctx, getKeyMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyMetadataPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetKeyMetadata successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKeyMetadata(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKeyMetadataOptions model
				getKeyMetadataOptionsModel := new(ibmkeyprotectapiv2.GetKeyMetadataOptions)
				getKeyMetadataOptionsModel.ID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyMetadataOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKeyMetadata with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyMetadataOptions model
				getKeyMetadataOptionsModel := new(ibmkeyprotectapiv2.GetKeyMetadataOptions)
				getKeyMetadataOptionsModel.ID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyMetadataOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKeyMetadataOptions model with no property values
				getKeyMetadataOptionsModelNew := new(ibmkeyprotectapiv2.GetKeyMetadataOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKeyMetadata successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyMetadataOptions model
				getKeyMetadataOptionsModel := new(ibmkeyprotectapiv2.GetKeyMetadataOptions)
				getKeyMetadataOptionsModel.ID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyMetadataOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyMetadataOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyMetadataOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKeyMetadata(getKeyMetadataOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PurgeKey(purgeKeyOptions *PurgeKeyOptions) - Operation response error`, func() {
		purgeKeyPath := "/api/v2/keys/testString/purge"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(purgeKeyPath))
					Expect(req.Method).To(Equal("DELETE"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PurgeKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PurgeKeyOptions model
				purgeKeyOptionsModel := new(ibmkeyprotectapiv2.PurgeKeyOptions)
				purgeKeyOptionsModel.ID = core.StringPtr("testString")
				purgeKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				purgeKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				purgeKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				purgeKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				purgeKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.PurgeKey(purgeKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.PurgeKey(purgeKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PurgeKey(purgeKeyOptions *PurgeKeyOptions)`, func() {
		purgeKeyPath := "/api/v2/keys/testString/purge"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(purgeKeyPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke PurgeKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the PurgeKeyOptions model
				purgeKeyOptionsModel := new(ibmkeyprotectapiv2.PurgeKeyOptions)
				purgeKeyOptionsModel.ID = core.StringPtr("testString")
				purgeKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				purgeKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				purgeKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				purgeKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				purgeKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.PurgeKeyWithContext(ctx, purgeKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.PurgeKey(purgeKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.PurgeKeyWithContext(ctx, purgeKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(purgeKeyPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"type": "application/vnd.ibm.kms.key+json", "id": "ID", "name": "Name", "aliases": ["Aliases"], "description": "Description", "tags": ["Tags"], "state": 0, "expirationDate": "2035-03-21T00:00:00.000Z", "extractable": true, "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:key:<key-id>", "imported": false, "keyRingID": "KeyRingID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "algorithmType": "AES", "algorithmMetadata": {"bitLength": "256", "mode": "CBC_PAD"}, "algorithmBitSize": 256, "algorithmMode": "CBC_PAD", "nonactiveStateReason": 20, "lastUpdateDate": "2000-03-21T00:00:00.000Z", "lastRotateDate": "2000-03-21T00:00:00.000Z", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}, "dualAuthDelete": {"enabled": true, "keySetForDeletion": true, "authExpiration": "2000-03-21T00:00:00.000Z"}, "rotation": {"enabled": true, "interval_month": 3}, "deleted": false, "deletionDate": "2000-03-21T00:00:00.000Z", "deletedBy": "DeletedBy", "restoreExpirationDate": "2000-03-21T00:00:00.000Z", "restoreAllowed": true, "purgeAllowed": true, "purgeAllowedFrom": "2000-03-21T00:00:00.000Z", "purgeScheduledOn": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke PurgeKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.PurgeKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PurgeKeyOptions model
				purgeKeyOptionsModel := new(ibmkeyprotectapiv2.PurgeKeyOptions)
				purgeKeyOptionsModel.ID = core.StringPtr("testString")
				purgeKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				purgeKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				purgeKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				purgeKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				purgeKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.PurgeKey(purgeKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PurgeKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PurgeKeyOptions model
				purgeKeyOptionsModel := new(ibmkeyprotectapiv2.PurgeKeyOptions)
				purgeKeyOptionsModel.ID = core.StringPtr("testString")
				purgeKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				purgeKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				purgeKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				purgeKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				purgeKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.PurgeKey(purgeKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PurgeKeyOptions model with no property values
				purgeKeyOptionsModelNew := new(ibmkeyprotectapiv2.PurgeKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.PurgeKey(purgeKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke PurgeKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PurgeKeyOptions model
				purgeKeyOptionsModel := new(ibmkeyprotectapiv2.PurgeKeyOptions)
				purgeKeyOptionsModel.ID = core.StringPtr("testString")
				purgeKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				purgeKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				purgeKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				purgeKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				purgeKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.PurgeKey(purgeKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`RestoreKey(restoreKeyOptions *RestoreKeyOptions)`, func() {
		restoreKeyPath := "/api/v2/keys/testString/restore"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(restoreKeyPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/vnd.ibm.kms.key+json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `This is a mock binary response.`)
				}))
			})
			It(`Invoke RestoreKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the RestoreKeyOptions model
				restoreKeyOptionsModel := new(ibmkeyprotectapiv2.RestoreKeyOptions)
				restoreKeyOptionsModel.ID = core.StringPtr("testString")
				restoreKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				restoreKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				restoreKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				restoreKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				restoreKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.RestoreKeyWithContext(ctx, restoreKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.RestoreKey(restoreKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.RestoreKeyWithContext(ctx, restoreKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(restoreKeyPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					// Set mock response
					res.Header().Set("Content-type", "application/vnd.ibm.kms.key+json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `This is a mock binary response.`)
				}))
			})
			It(`Invoke RestoreKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.RestoreKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the RestoreKeyOptions model
				restoreKeyOptionsModel := new(ibmkeyprotectapiv2.RestoreKeyOptions)
				restoreKeyOptionsModel.ID = core.StringPtr("testString")
				restoreKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				restoreKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				restoreKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				restoreKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				restoreKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.RestoreKey(restoreKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke RestoreKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the RestoreKeyOptions model
				restoreKeyOptionsModel := new(ibmkeyprotectapiv2.RestoreKeyOptions)
				restoreKeyOptionsModel.ID = core.StringPtr("testString")
				restoreKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				restoreKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				restoreKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				restoreKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				restoreKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.RestoreKey(restoreKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the RestoreKeyOptions model with no property values
				restoreKeyOptionsModelNew := new(ibmkeyprotectapiv2.RestoreKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.RestoreKey(restoreKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke RestoreKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the RestoreKeyOptions model
				restoreKeyOptionsModel := new(ibmkeyprotectapiv2.RestoreKeyOptions)
				restoreKeyOptionsModel.ID = core.StringPtr("testString")
				restoreKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				restoreKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				restoreKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				restoreKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				restoreKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.RestoreKey(restoreKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify empty byte buffer.
				Expect(result).ToNot(BeNil())
				buffer, operationErr := io.ReadAll(result)
				Expect(operationErr).To(BeNil())
				Expect(buffer).ToNot(BeNil())
				Expect(len(buffer)).To(Equal(0))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKeyVersions(getKeyVersionsOptions *GetKeyVersionsOptions) - Operation response error`, func() {
		getKeyVersionsPath := "/api/v2/keys/testString/versions"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyVersionsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// TODO: Add check for allKeyStates query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKeyVersions with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyVersionsOptions model
				getKeyVersionsOptionsModel := new(ibmkeyprotectapiv2.GetKeyVersionsOptions)
				getKeyVersionsOptionsModel.ID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyVersionsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyVersionsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeyVersionsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeyVersionsOptionsModel.TotalCount = core.BoolPtr(true)
				getKeyVersionsOptionsModel.AllKeyStates = core.BoolPtr(false)
				getKeyVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKeyVersions(getKeyVersionsOptions *GetKeyVersionsOptions)`, func() {
		getKeyVersionsPath := "/api/v2/keys/testString/versions"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyVersionsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// TODO: Add check for allKeyStates query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetKeyVersions successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKeyVersionsOptions model
				getKeyVersionsOptionsModel := new(ibmkeyprotectapiv2.GetKeyVersionsOptions)
				getKeyVersionsOptionsModel.ID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyVersionsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyVersionsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeyVersionsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeyVersionsOptionsModel.TotalCount = core.BoolPtr(true)
				getKeyVersionsOptionsModel.AllKeyStates = core.BoolPtr(false)
				getKeyVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKeyVersionsWithContext(ctx, getKeyVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKeyVersionsWithContext(ctx, getKeyVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKeyVersionsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// TODO: Add check for allKeyStates query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke GetKeyVersions successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKeyVersions(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKeyVersionsOptions model
				getKeyVersionsOptionsModel := new(ibmkeyprotectapiv2.GetKeyVersionsOptions)
				getKeyVersionsOptionsModel.ID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyVersionsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyVersionsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeyVersionsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeyVersionsOptionsModel.TotalCount = core.BoolPtr(true)
				getKeyVersionsOptionsModel.AllKeyStates = core.BoolPtr(false)
				getKeyVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKeyVersions with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyVersionsOptions model
				getKeyVersionsOptionsModel := new(ibmkeyprotectapiv2.GetKeyVersionsOptions)
				getKeyVersionsOptionsModel.ID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyVersionsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyVersionsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeyVersionsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeyVersionsOptionsModel.TotalCount = core.BoolPtr(true)
				getKeyVersionsOptionsModel.AllKeyStates = core.BoolPtr(false)
				getKeyVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKeyVersionsOptions model with no property values
				getKeyVersionsOptionsModelNew := new(ibmkeyprotectapiv2.GetKeyVersionsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKeyVersions successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKeyVersionsOptions model
				getKeyVersionsOptionsModel := new(ibmkeyprotectapiv2.GetKeyVersionsOptions)
				getKeyVersionsOptionsModel.ID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKeyVersionsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKeyVersionsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getKeyVersionsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getKeyVersionsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKeyVersionsOptionsModel.TotalCount = core.BoolPtr(true)
				getKeyVersionsOptionsModel.AllKeyStates = core.BoolPtr(false)
				getKeyVersionsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKeyVersions(getKeyVersionsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`WrapKey(wrapKeyOptions *WrapKeyOptions) - Operation response error`, func() {
		wrapKeyPath := "/api/v2/keys/testString/actions/wrap"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(wrapKeyPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke WrapKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the WrapKeyOptions model
				wrapKeyOptionsModel := new(ibmkeyprotectapiv2.WrapKeyOptions)
				wrapKeyOptionsModel.ID = core.StringPtr("testString")
				wrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				wrapKeyOptionsModel.KeyActionWrapBody = CreateMockReader("This is a mock file.")
				wrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				wrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				wrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.WrapKey(wrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.WrapKey(wrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`WrapKey(wrapKeyOptions *WrapKeyOptions)`, func() {
		wrapKeyPath := "/api/v2/keys/testString/actions/wrap"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(wrapKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"plaintext": "Plaintext", "ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke WrapKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the WrapKeyOptions model
				wrapKeyOptionsModel := new(ibmkeyprotectapiv2.WrapKeyOptions)
				wrapKeyOptionsModel.ID = core.StringPtr("testString")
				wrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				wrapKeyOptionsModel.KeyActionWrapBody = CreateMockReader("This is a mock file.")
				wrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				wrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				wrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.WrapKeyWithContext(ctx, wrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.WrapKey(wrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.WrapKeyWithContext(ctx, wrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(wrapKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"plaintext": "Plaintext", "ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke WrapKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.WrapKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the WrapKeyOptions model
				wrapKeyOptionsModel := new(ibmkeyprotectapiv2.WrapKeyOptions)
				wrapKeyOptionsModel.ID = core.StringPtr("testString")
				wrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				wrapKeyOptionsModel.KeyActionWrapBody = CreateMockReader("This is a mock file.")
				wrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				wrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				wrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.WrapKey(wrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke WrapKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the WrapKeyOptions model
				wrapKeyOptionsModel := new(ibmkeyprotectapiv2.WrapKeyOptions)
				wrapKeyOptionsModel.ID = core.StringPtr("testString")
				wrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				wrapKeyOptionsModel.KeyActionWrapBody = CreateMockReader("This is a mock file.")
				wrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				wrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				wrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.WrapKey(wrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the WrapKeyOptions model with no property values
				wrapKeyOptionsModelNew := new(ibmkeyprotectapiv2.WrapKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.WrapKey(wrapKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke WrapKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the WrapKeyOptions model
				wrapKeyOptionsModel := new(ibmkeyprotectapiv2.WrapKeyOptions)
				wrapKeyOptionsModel.ID = core.StringPtr("testString")
				wrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				wrapKeyOptionsModel.KeyActionWrapBody = CreateMockReader("This is a mock file.")
				wrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				wrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				wrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.WrapKey(wrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UnwrapKey(unwrapKeyOptions *UnwrapKeyOptions) - Operation response error`, func() {
		unwrapKeyPath := "/api/v2/keys/testString/actions/unwrap"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unwrapKeyPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke UnwrapKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the UnwrapKeyOptions model
				unwrapKeyOptionsModel := new(ibmkeyprotectapiv2.UnwrapKeyOptions)
				unwrapKeyOptionsModel.ID = core.StringPtr("testString")
				unwrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				unwrapKeyOptionsModel.KeyActionUnwrapBody = CreateMockReader("This is a mock file.")
				unwrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				unwrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				unwrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UnwrapKey(unwrapKeyOptions *UnwrapKeyOptions)`, func() {
		unwrapKeyPath := "/api/v2/keys/testString/actions/unwrap"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unwrapKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"plaintext": "Plaintext", "ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke UnwrapKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the UnwrapKeyOptions model
				unwrapKeyOptionsModel := new(ibmkeyprotectapiv2.UnwrapKeyOptions)
				unwrapKeyOptionsModel.ID = core.StringPtr("testString")
				unwrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				unwrapKeyOptionsModel.KeyActionUnwrapBody = CreateMockReader("This is a mock file.")
				unwrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				unwrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				unwrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.UnwrapKeyWithContext(ctx, unwrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.UnwrapKeyWithContext(ctx, unwrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unwrapKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"plaintext": "Plaintext", "ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke UnwrapKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.UnwrapKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the UnwrapKeyOptions model
				unwrapKeyOptionsModel := new(ibmkeyprotectapiv2.UnwrapKeyOptions)
				unwrapKeyOptionsModel.ID = core.StringPtr("testString")
				unwrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				unwrapKeyOptionsModel.KeyActionUnwrapBody = CreateMockReader("This is a mock file.")
				unwrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				unwrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				unwrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke UnwrapKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the UnwrapKeyOptions model
				unwrapKeyOptionsModel := new(ibmkeyprotectapiv2.UnwrapKeyOptions)
				unwrapKeyOptionsModel.ID = core.StringPtr("testString")
				unwrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				unwrapKeyOptionsModel.KeyActionUnwrapBody = CreateMockReader("This is a mock file.")
				unwrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				unwrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				unwrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the UnwrapKeyOptions model with no property values
				unwrapKeyOptionsModelNew := new(ibmkeyprotectapiv2.UnwrapKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke UnwrapKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the UnwrapKeyOptions model
				unwrapKeyOptionsModel := new(ibmkeyprotectapiv2.UnwrapKeyOptions)
				unwrapKeyOptionsModel.ID = core.StringPtr("testString")
				unwrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				unwrapKeyOptionsModel.KeyActionUnwrapBody = CreateMockReader("This is a mock file.")
				unwrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				unwrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				unwrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.UnwrapKey(unwrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`RewrapKey(rewrapKeyOptions *RewrapKeyOptions) - Operation response error`, func() {
		rewrapKeyPath := "/api/v2/keys/testString/actions/rewrap"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(rewrapKeyPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke RewrapKey with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the RewrapKeyOptions model
				rewrapKeyOptionsModel := new(ibmkeyprotectapiv2.RewrapKeyOptions)
				rewrapKeyOptionsModel.ID = core.StringPtr("testString")
				rewrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				rewrapKeyOptionsModel.KeyActionRewrapBody = CreateMockReader("This is a mock file.")
				rewrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				rewrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				rewrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.RewrapKey(rewrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.RewrapKey(rewrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`RewrapKey(rewrapKeyOptions *RewrapKeyOptions)`, func() {
		rewrapKeyPath := "/api/v2/keys/testString/actions/rewrap"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(rewrapKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke RewrapKey successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the RewrapKeyOptions model
				rewrapKeyOptionsModel := new(ibmkeyprotectapiv2.RewrapKeyOptions)
				rewrapKeyOptionsModel.ID = core.StringPtr("testString")
				rewrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				rewrapKeyOptionsModel.KeyActionRewrapBody = CreateMockReader("This is a mock file.")
				rewrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				rewrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				rewrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.RewrapKeyWithContext(ctx, rewrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.RewrapKey(rewrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.RewrapKeyWithContext(ctx, rewrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(rewrapKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"ciphertext": "Ciphertext", "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}, "rewrappedKeyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab"}}`)
				}))
			})
			It(`Invoke RewrapKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.RewrapKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the RewrapKeyOptions model
				rewrapKeyOptionsModel := new(ibmkeyprotectapiv2.RewrapKeyOptions)
				rewrapKeyOptionsModel.ID = core.StringPtr("testString")
				rewrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				rewrapKeyOptionsModel.KeyActionRewrapBody = CreateMockReader("This is a mock file.")
				rewrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				rewrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				rewrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.RewrapKey(rewrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke RewrapKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the RewrapKeyOptions model
				rewrapKeyOptionsModel := new(ibmkeyprotectapiv2.RewrapKeyOptions)
				rewrapKeyOptionsModel.ID = core.StringPtr("testString")
				rewrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				rewrapKeyOptionsModel.KeyActionRewrapBody = CreateMockReader("This is a mock file.")
				rewrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				rewrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				rewrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.RewrapKey(rewrapKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the RewrapKeyOptions model with no property values
				rewrapKeyOptionsModelNew := new(ibmkeyprotectapiv2.RewrapKeyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.RewrapKey(rewrapKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke RewrapKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the RewrapKeyOptions model
				rewrapKeyOptionsModel := new(ibmkeyprotectapiv2.RewrapKeyOptions)
				rewrapKeyOptionsModel.ID = core.StringPtr("testString")
				rewrapKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				rewrapKeyOptionsModel.KeyActionRewrapBody = CreateMockReader("This is a mock file.")
				rewrapKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				rewrapKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				rewrapKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.RewrapKey(rewrapKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`RotateKey(rotateKeyOptions *RotateKeyOptions)`, func() {
		rotateKeyPath := "/api/v2/keys/testString/actions/rotate"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(rotateKeyPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Prefer"]).ToNot(BeNil())
					Expect(req.Header["Prefer"][0]).To(Equal(fmt.Sprintf("%v", "return=representation")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke RotateKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.RotateKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the RotateKeyOptions model
				rotateKeyOptionsModel := new(ibmkeyprotectapiv2.RotateKeyOptions)
				rotateKeyOptionsModel.ID = core.StringPtr("testString")
				rotateKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				rotateKeyOptionsModel.KeyActionRotateBody = CreateMockReader("This is a mock file.")
				rotateKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				rotateKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				rotateKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				rotateKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.RotateKey(rotateKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke RotateKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the RotateKeyOptions model
				rotateKeyOptionsModel := new(ibmkeyprotectapiv2.RotateKeyOptions)
				rotateKeyOptionsModel.ID = core.StringPtr("testString")
				rotateKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				rotateKeyOptionsModel.KeyActionRotateBody = CreateMockReader("This is a mock file.")
				rotateKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				rotateKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				rotateKeyOptionsModel.Prefer = core.StringPtr("return=representation")
				rotateKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.RotateKey(rotateKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the RotateKeyOptions model with no property values
				rotateKeyOptionsModelNew := new(ibmkeyprotectapiv2.RotateKeyOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.RotateKey(rotateKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`SetKeyForDeletion(setKeyForDeletionOptions *SetKeyForDeletionOptions)`, func() {
		setKeyForDeletionPath := "/api/v2/keys/testString/actions/setKeyForDeletion"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(setKeyForDeletionPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke SetKeyForDeletion successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.SetKeyForDeletion(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the SetKeyForDeletionOptions model
				setKeyForDeletionOptionsModel := new(ibmkeyprotectapiv2.SetKeyForDeletionOptions)
				setKeyForDeletionOptionsModel.ID = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.BluemixInstance = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.CorrelationID = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.SetKeyForDeletion(setKeyForDeletionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke SetKeyForDeletion with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the SetKeyForDeletionOptions model
				setKeyForDeletionOptionsModel := new(ibmkeyprotectapiv2.SetKeyForDeletionOptions)
				setKeyForDeletionOptionsModel.ID = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.BluemixInstance = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.CorrelationID = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				setKeyForDeletionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.SetKeyForDeletion(setKeyForDeletionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the SetKeyForDeletionOptions model with no property values
				setKeyForDeletionOptionsModelNew := new(ibmkeyprotectapiv2.SetKeyForDeletionOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.SetKeyForDeletion(setKeyForDeletionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`UnsetKeyForDeletion(unsetKeyForDeletionOptions *UnsetKeyForDeletionOptions)`, func() {
		unsetKeyForDeletionPath := "/api/v2/keys/testString/actions/unsetKeyForDeletion"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(unsetKeyForDeletionPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke UnsetKeyForDeletion successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.UnsetKeyForDeletion(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the UnsetKeyForDeletionOptions model
				unsetKeyForDeletionOptionsModel := new(ibmkeyprotectapiv2.UnsetKeyForDeletionOptions)
				unsetKeyForDeletionOptionsModel.ID = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.BluemixInstance = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.CorrelationID = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.UnsetKeyForDeletion(unsetKeyForDeletionOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke UnsetKeyForDeletion with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the UnsetKeyForDeletionOptions model
				unsetKeyForDeletionOptionsModel := new(ibmkeyprotectapiv2.UnsetKeyForDeletionOptions)
				unsetKeyForDeletionOptionsModel.ID = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.BluemixInstance = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.CorrelationID = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				unsetKeyForDeletionOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.UnsetKeyForDeletion(unsetKeyForDeletionOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the UnsetKeyForDeletionOptions model with no property values
				unsetKeyForDeletionOptionsModelNew := new(ibmkeyprotectapiv2.UnsetKeyForDeletionOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.UnsetKeyForDeletion(unsetKeyForDeletionOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`EnableKey(enableKeyOptions *EnableKeyOptions)`, func() {
		enableKeyPath := "/api/v2/keys/testString/actions/enable"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(enableKeyPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke EnableKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.EnableKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the EnableKeyOptions model
				enableKeyOptionsModel := new(ibmkeyprotectapiv2.EnableKeyOptions)
				enableKeyOptionsModel.ID = core.StringPtr("testString")
				enableKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				enableKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				enableKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				enableKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.EnableKey(enableKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke EnableKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the EnableKeyOptions model
				enableKeyOptionsModel := new(ibmkeyprotectapiv2.EnableKeyOptions)
				enableKeyOptionsModel.ID = core.StringPtr("testString")
				enableKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				enableKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				enableKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				enableKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.EnableKey(enableKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the EnableKeyOptions model with no property values
				enableKeyOptionsModelNew := new(ibmkeyprotectapiv2.EnableKeyOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.EnableKey(enableKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DisableKey(disableKeyOptions *DisableKeyOptions)`, func() {
		disableKeyPath := "/api/v2/keys/testString/actions/disable"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(disableKeyPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DisableKey successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.DisableKey(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DisableKeyOptions model
				disableKeyOptionsModel := new(ibmkeyprotectapiv2.DisableKeyOptions)
				disableKeyOptionsModel.ID = core.StringPtr("testString")
				disableKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				disableKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				disableKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				disableKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.DisableKey(disableKeyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DisableKey with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DisableKeyOptions model
				disableKeyOptionsModel := new(ibmkeyprotectapiv2.DisableKeyOptions)
				disableKeyOptionsModel.ID = core.StringPtr("testString")
				disableKeyOptionsModel.BluemixInstance = core.StringPtr("testString")
				disableKeyOptionsModel.CorrelationID = core.StringPtr("testString")
				disableKeyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				disableKeyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.DisableKey(disableKeyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DisableKeyOptions model with no property values
				disableKeyOptionsModelNew := new(ibmkeyprotectapiv2.DisableKeyOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.DisableKey(disableKeyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`SyncAssociatedResources(syncAssociatedResourcesOptions *SyncAssociatedResourcesOptions)`, func() {
		syncAssociatedResourcesPath := "/api/v2/keys/testString/actions/sync"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(syncAssociatedResourcesPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke SyncAssociatedResources successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.SyncAssociatedResources(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the SyncAssociatedResourcesOptions model
				syncAssociatedResourcesOptionsModel := new(ibmkeyprotectapiv2.SyncAssociatedResourcesOptions)
				syncAssociatedResourcesOptionsModel.ID = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.BluemixInstance = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.CorrelationID = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.SyncAssociatedResources(syncAssociatedResourcesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke SyncAssociatedResources with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the SyncAssociatedResourcesOptions model
				syncAssociatedResourcesOptionsModel := new(ibmkeyprotectapiv2.SyncAssociatedResourcesOptions)
				syncAssociatedResourcesOptionsModel.ID = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.BluemixInstance = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.CorrelationID = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				syncAssociatedResourcesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.SyncAssociatedResources(syncAssociatedResourcesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the SyncAssociatedResourcesOptions model with no property values
				syncAssociatedResourcesOptionsModelNew := new(ibmkeyprotectapiv2.SyncAssociatedResourcesOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.SyncAssociatedResources(syncAssociatedResourcesOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PutPolicy(putPolicyOptions *PutPolicyOptions) - Operation response error`, func() {
		putPolicyPath := "/api/v2/keys/testString/policies"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putPolicyPath))
					Expect(req.Method).To(Equal("PUT"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"dualAuthDelete"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PutPolicy with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KeyPolicyDualAuthDeleteDualAuthDelete model
				keyPolicyDualAuthDeleteDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete)
				keyPolicyDualAuthDeleteDualAuthDeleteModel.Enabled = core.BoolPtr(true)

				// Construct an instance of the KeyPolicyDualAuthDelete model
				keyPolicyDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDelete)
				keyPolicyDualAuthDeleteModel.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
				keyPolicyDualAuthDeleteModel.DualAuthDelete = keyPolicyDualAuthDeleteDualAuthDeleteModel

				// Construct an instance of the SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
				setKeyPoliciesOneOfModel := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete)
				setKeyPoliciesOneOfModel.Metadata = collectionMetadataModel
				setKeyPoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel}

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibmkeyprotectapiv2.PutPolicyOptions)
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				putPolicyOptionsModel.KeyPolicyPutBody = setKeyPoliciesOneOfModel
				putPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				putPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				putPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PutPolicy(putPolicyOptions *PutPolicyOptions)`, func() {
		putPolicyPath := "/api/v2/keys/testString/policies"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putPolicyPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"dualAuthDelete"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "UpdatedBy", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}`)
				}))
			})
			It(`Invoke PutPolicy successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KeyPolicyDualAuthDeleteDualAuthDelete model
				keyPolicyDualAuthDeleteDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete)
				keyPolicyDualAuthDeleteDualAuthDeleteModel.Enabled = core.BoolPtr(true)

				// Construct an instance of the KeyPolicyDualAuthDelete model
				keyPolicyDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDelete)
				keyPolicyDualAuthDeleteModel.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
				keyPolicyDualAuthDeleteModel.DualAuthDelete = keyPolicyDualAuthDeleteDualAuthDeleteModel

				// Construct an instance of the SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
				setKeyPoliciesOneOfModel := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete)
				setKeyPoliciesOneOfModel.Metadata = collectionMetadataModel
				setKeyPoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel}

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibmkeyprotectapiv2.PutPolicyOptions)
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				putPolicyOptionsModel.KeyPolicyPutBody = setKeyPoliciesOneOfModel
				putPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				putPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				putPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.PutPolicyWithContext(ctx, putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.PutPolicyWithContext(ctx, putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putPolicyPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"dualAuthDelete"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "UpdatedBy", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}`)
				}))
			})
			It(`Invoke PutPolicy successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.PutPolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KeyPolicyDualAuthDeleteDualAuthDelete model
				keyPolicyDualAuthDeleteDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete)
				keyPolicyDualAuthDeleteDualAuthDeleteModel.Enabled = core.BoolPtr(true)

				// Construct an instance of the KeyPolicyDualAuthDelete model
				keyPolicyDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDelete)
				keyPolicyDualAuthDeleteModel.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
				keyPolicyDualAuthDeleteModel.DualAuthDelete = keyPolicyDualAuthDeleteDualAuthDeleteModel

				// Construct an instance of the SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
				setKeyPoliciesOneOfModel := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete)
				setKeyPoliciesOneOfModel.Metadata = collectionMetadataModel
				setKeyPoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel}

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibmkeyprotectapiv2.PutPolicyOptions)
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				putPolicyOptionsModel.KeyPolicyPutBody = setKeyPoliciesOneOfModel
				putPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				putPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				putPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PutPolicy with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KeyPolicyDualAuthDeleteDualAuthDelete model
				keyPolicyDualAuthDeleteDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete)
				keyPolicyDualAuthDeleteDualAuthDeleteModel.Enabled = core.BoolPtr(true)

				// Construct an instance of the KeyPolicyDualAuthDelete model
				keyPolicyDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDelete)
				keyPolicyDualAuthDeleteModel.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
				keyPolicyDualAuthDeleteModel.DualAuthDelete = keyPolicyDualAuthDeleteDualAuthDeleteModel

				// Construct an instance of the SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
				setKeyPoliciesOneOfModel := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete)
				setKeyPoliciesOneOfModel.Metadata = collectionMetadataModel
				setKeyPoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel}

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibmkeyprotectapiv2.PutPolicyOptions)
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				putPolicyOptionsModel.KeyPolicyPutBody = setKeyPoliciesOneOfModel
				putPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				putPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				putPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PutPolicyOptions model with no property values
				putPolicyOptionsModelNew := new(ibmkeyprotectapiv2.PutPolicyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.PutPolicy(putPolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke PutPolicy successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KeyPolicyDualAuthDeleteDualAuthDelete model
				keyPolicyDualAuthDeleteDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete)
				keyPolicyDualAuthDeleteDualAuthDeleteModel.Enabled = core.BoolPtr(true)

				// Construct an instance of the KeyPolicyDualAuthDelete model
				keyPolicyDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDelete)
				keyPolicyDualAuthDeleteModel.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
				keyPolicyDualAuthDeleteModel.DualAuthDelete = keyPolicyDualAuthDeleteDualAuthDeleteModel

				// Construct an instance of the SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
				setKeyPoliciesOneOfModel := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete)
				setKeyPoliciesOneOfModel.Metadata = collectionMetadataModel
				setKeyPoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel}

				// Construct an instance of the PutPolicyOptions model
				putPolicyOptionsModel := new(ibmkeyprotectapiv2.PutPolicyOptions)
				putPolicyOptionsModel.ID = core.StringPtr("testString")
				putPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				putPolicyOptionsModel.KeyPolicyPutBody = setKeyPoliciesOneOfModel
				putPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				putPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				putPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				putPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.PutPolicy(putPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPolicy(getPolicyOptions *GetPolicyOptions) - Operation response error`, func() {
		getPolicyPath := "/api/v2/keys/testString/policies"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPolicyPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"dualAuthDelete"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetPolicy with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibmkeyprotectapiv2.GetPolicyOptions)
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetPolicy(getPolicyOptions *GetPolicyOptions)`, func() {
		getPolicyPath := "/api/v2/keys/testString/policies"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPolicyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"dualAuthDelete"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "UpdatedBy", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}`)
				}))
			})
			It(`Invoke GetPolicy successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibmkeyprotectapiv2.GetPolicyOptions)
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetPolicyWithContext(ctx, getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetPolicyWithContext(ctx, getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getPolicyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"dualAuthDelete"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"id": "ID", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance>:policy:<policy-id>", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "lastUpdateDate": "2000-03-21T00:00:00.000Z", "updatedBy": "UpdatedBy", "type": "application/vnd.ibm.kms.policy+json", "dualAuthDelete": {"enabled": true}}]}`)
				}))
			})
			It(`Invoke GetPolicy successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetPolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibmkeyprotectapiv2.GetPolicyOptions)
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetPolicy with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibmkeyprotectapiv2.GetPolicyOptions)
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetPolicyOptions model with no property values
				getPolicyOptionsModelNew := new(ibmkeyprotectapiv2.GetPolicyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetPolicy(getPolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetPolicy successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetPolicyOptions model
				getPolicyOptionsModel := new(ibmkeyprotectapiv2.GetPolicyOptions)
				getPolicyOptionsModel.ID = core.StringPtr("testString")
				getPolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getPolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getPolicyOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getPolicyOptionsModel.Policy = core.StringPtr("dualAuthDelete")
				getPolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetPolicy(getPolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PutInstancePolicy(putInstancePolicyOptions *PutInstancePolicyOptions)`, func() {
		putInstancePolicyPath := "/api/v2/instance/policies"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(putInstancePolicyPath))
					Expect(req.Method).To(Equal("PUT"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"allowedNetwork"}))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke PutInstancePolicy successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.PutInstancePolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the InstancePolicyAllowedNetworkPolicyDataAttributes model
				instancePolicyAllowedNetworkPolicyDataAttributesModel := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyDataAttributes)
				instancePolicyAllowedNetworkPolicyDataAttributesModel.AllowedNetwork = core.StringPtr("private-only")

				// Construct an instance of the InstancePolicyAllowedNetworkPolicyData model
				instancePolicyAllowedNetworkPolicyDataModel := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData)
				instancePolicyAllowedNetworkPolicyDataModel.Enabled = core.BoolPtr(true)
				instancePolicyAllowedNetworkPolicyDataModel.Attributes = instancePolicyAllowedNetworkPolicyDataAttributesModel

				// Construct an instance of the SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem)
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyType = core.StringPtr("allowedNetwork")
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyData = instancePolicyAllowedNetworkPolicyDataModel

				// Construct an instance of the SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
				setInstancePoliciesOneOfModel := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork)
				setInstancePoliciesOneOfModel.Metadata = collectionMetadataModel
				setInstancePoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem{*setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel}

				// Construct an instance of the PutInstancePolicyOptions model
				putInstancePolicyOptionsModel := new(ibmkeyprotectapiv2.PutInstancePolicyOptions)
				putInstancePolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				putInstancePolicyOptionsModel.InstancePolicyPutBody = setInstancePoliciesOneOfModel
				putInstancePolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				putInstancePolicyOptionsModel.Policy = core.StringPtr("allowedNetwork")
				putInstancePolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.PutInstancePolicy(putInstancePolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke PutInstancePolicy with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.policy+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the InstancePolicyAllowedNetworkPolicyDataAttributes model
				instancePolicyAllowedNetworkPolicyDataAttributesModel := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyDataAttributes)
				instancePolicyAllowedNetworkPolicyDataAttributesModel.AllowedNetwork = core.StringPtr("private-only")

				// Construct an instance of the InstancePolicyAllowedNetworkPolicyData model
				instancePolicyAllowedNetworkPolicyDataModel := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData)
				instancePolicyAllowedNetworkPolicyDataModel.Enabled = core.BoolPtr(true)
				instancePolicyAllowedNetworkPolicyDataModel.Attributes = instancePolicyAllowedNetworkPolicyDataAttributesModel

				// Construct an instance of the SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem)
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyType = core.StringPtr("allowedNetwork")
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyData = instancePolicyAllowedNetworkPolicyDataModel

				// Construct an instance of the SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
				setInstancePoliciesOneOfModel := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork)
				setInstancePoliciesOneOfModel.Metadata = collectionMetadataModel
				setInstancePoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem{*setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel}

				// Construct an instance of the PutInstancePolicyOptions model
				putInstancePolicyOptionsModel := new(ibmkeyprotectapiv2.PutInstancePolicyOptions)
				putInstancePolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				putInstancePolicyOptionsModel.InstancePolicyPutBody = setInstancePoliciesOneOfModel
				putInstancePolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				putInstancePolicyOptionsModel.Policy = core.StringPtr("allowedNetwork")
				putInstancePolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.PutInstancePolicy(putInstancePolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the PutInstancePolicyOptions model with no property values
				putInstancePolicyOptionsModelNew := new(ibmkeyprotectapiv2.PutInstancePolicyOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.PutInstancePolicy(putInstancePolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetInstancePolicy(getInstancePolicyOptions *GetInstancePolicyOptions) - Operation response error`, func() {
		getInstancePolicyPath := "/api/v2/instance/policies"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getInstancePolicyPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"allowedNetwork"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetInstancePolicy with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetInstancePolicyOptions model
				getInstancePolicyOptionsModel := new(ibmkeyprotectapiv2.GetInstancePolicyOptions)
				getInstancePolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getInstancePolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getInstancePolicyOptionsModel.Policy = core.StringPtr("allowedNetwork")
				getInstancePolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetInstancePolicy(getInstancePolicyOptions *GetInstancePolicyOptions)`, func() {
		getInstancePolicyPath := "/api/v2/instance/policies"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getInstancePolicyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"allowedNetwork"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "updatedBy": "UpdatedBy", "lastUpdated": "2000-03-21T00:00:00.000Z", "policy_type": "PolicyType", "policy_data": {"enabled": true, "attributes": {"allowed_network": "public-and-private"}}}]}`)
				}))
			})
			It(`Invoke GetInstancePolicy successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetInstancePolicyOptions model
				getInstancePolicyOptionsModel := new(ibmkeyprotectapiv2.GetInstancePolicyOptions)
				getInstancePolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getInstancePolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getInstancePolicyOptionsModel.Policy = core.StringPtr("allowedNetwork")
				getInstancePolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetInstancePolicyWithContext(ctx, getInstancePolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetInstancePolicyWithContext(ctx, getInstancePolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getInstancePolicyPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["policy"]).To(Equal([]string{"allowedNetwork"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy", "updatedBy": "UpdatedBy", "lastUpdated": "2000-03-21T00:00:00.000Z", "policy_type": "PolicyType", "policy_data": {"enabled": true, "attributes": {"allowed_network": "public-and-private"}}}]}`)
				}))
			})
			It(`Invoke GetInstancePolicy successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetInstancePolicy(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetInstancePolicyOptions model
				getInstancePolicyOptionsModel := new(ibmkeyprotectapiv2.GetInstancePolicyOptions)
				getInstancePolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getInstancePolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getInstancePolicyOptionsModel.Policy = core.StringPtr("allowedNetwork")
				getInstancePolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetInstancePolicy with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetInstancePolicyOptions model
				getInstancePolicyOptionsModel := new(ibmkeyprotectapiv2.GetInstancePolicyOptions)
				getInstancePolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getInstancePolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getInstancePolicyOptionsModel.Policy = core.StringPtr("allowedNetwork")
				getInstancePolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetInstancePolicyOptions model with no property values
				getInstancePolicyOptionsModelNew := new(ibmkeyprotectapiv2.GetInstancePolicyOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetInstancePolicy successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetInstancePolicyOptions model
				getInstancePolicyOptionsModel := new(ibmkeyprotectapiv2.GetInstancePolicyOptions)
				getInstancePolicyOptionsModel.BluemixInstance = core.StringPtr("testString")
				getInstancePolicyOptionsModel.CorrelationID = core.StringPtr("testString")
				getInstancePolicyOptionsModel.Policy = core.StringPtr("allowedNetwork")
				getInstancePolicyOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetInstancePolicy(getInstancePolicyOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetAllowedIPPort(getAllowedIPPortOptions *GetAllowedIPPortOptions) - Operation response error`, func() {
		getAllowedIpPortPath := "/api/v2/instance/allowed_ip_port"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getAllowedIpPortPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetAllowedIPPort with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetAllowedIPPortOptions model
				getAllowedIpPortOptionsModel := new(ibmkeyprotectapiv2.GetAllowedIPPortOptions)
				getAllowedIpPortOptionsModel.BluemixInstance = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.CorrelationID = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetAllowedIPPort(getAllowedIPPortOptions *GetAllowedIPPortOptions)`, func() {
		getAllowedIpPortPath := "/api/v2/instance/allowed_ip_port"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getAllowedIpPortPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"private_endpoint_port": 8888}]}`)
				}))
			})
			It(`Invoke GetAllowedIPPort successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetAllowedIPPortOptions model
				getAllowedIpPortOptionsModel := new(ibmkeyprotectapiv2.GetAllowedIPPortOptions)
				getAllowedIpPortOptionsModel.BluemixInstance = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.CorrelationID = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetAllowedIPPortWithContext(ctx, getAllowedIpPortOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetAllowedIPPortWithContext(ctx, getAllowedIpPortOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getAllowedIpPortPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"private_endpoint_port": 8888}]}`)
				}))
			})
			It(`Invoke GetAllowedIPPort successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetAllowedIPPort(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetAllowedIPPortOptions model
				getAllowedIpPortOptionsModel := new(ibmkeyprotectapiv2.GetAllowedIPPortOptions)
				getAllowedIpPortOptionsModel.BluemixInstance = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.CorrelationID = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetAllowedIPPort with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetAllowedIPPortOptions model
				getAllowedIpPortOptionsModel := new(ibmkeyprotectapiv2.GetAllowedIPPortOptions)
				getAllowedIpPortOptionsModel.BluemixInstance = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.CorrelationID = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetAllowedIPPortOptions model with no property values
				getAllowedIpPortOptionsModelNew := new(ibmkeyprotectapiv2.GetAllowedIPPortOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetAllowedIPPort successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetAllowedIPPortOptions model
				getAllowedIpPortOptionsModel := new(ibmkeyprotectapiv2.GetAllowedIPPortOptions)
				getAllowedIpPortOptionsModel.BluemixInstance = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.CorrelationID = core.StringPtr("testString")
				getAllowedIpPortOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetAllowedIPPort(getAllowedIpPortOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PostImportToken(postImportTokenOptions *PostImportTokenOptions) - Operation response error`, func() {
		postImportTokenPath := "/api/v2/import_token"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(postImportTokenPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke PostImportToken with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PostImportTokenOptions model
				postImportTokenOptionsModel := new(ibmkeyprotectapiv2.PostImportTokenOptions)
				postImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				postImportTokenOptionsModel.Expiration = core.Float64Ptr(float64(600))
				postImportTokenOptionsModel.MaxAllowedRetrievals = core.Float64Ptr(float64(1))
				postImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				postImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				postImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.PostImportToken(postImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.PostImportToken(postImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`PostImportToken(postImportTokenOptions *PostImportTokenOptions)`, func() {
		postImportTokenPath := "/api/v2/import_token"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(postImportTokenPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1}`)
				}))
			})
			It(`Invoke PostImportToken successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the PostImportTokenOptions model
				postImportTokenOptionsModel := new(ibmkeyprotectapiv2.PostImportTokenOptions)
				postImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				postImportTokenOptionsModel.Expiration = core.Float64Ptr(float64(600))
				postImportTokenOptionsModel.MaxAllowedRetrievals = core.Float64Ptr(float64(1))
				postImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				postImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				postImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.PostImportTokenWithContext(ctx, postImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.PostImportToken(postImportTokenOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.PostImportTokenWithContext(ctx, postImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(postImportTokenPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1}`)
				}))
			})
			It(`Invoke PostImportToken successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.PostImportToken(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the PostImportTokenOptions model
				postImportTokenOptionsModel := new(ibmkeyprotectapiv2.PostImportTokenOptions)
				postImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				postImportTokenOptionsModel.Expiration = core.Float64Ptr(float64(600))
				postImportTokenOptionsModel.MaxAllowedRetrievals = core.Float64Ptr(float64(1))
				postImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				postImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				postImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.PostImportToken(postImportTokenOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke PostImportToken with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PostImportTokenOptions model
				postImportTokenOptionsModel := new(ibmkeyprotectapiv2.PostImportTokenOptions)
				postImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				postImportTokenOptionsModel.Expiration = core.Float64Ptr(float64(600))
				postImportTokenOptionsModel.MaxAllowedRetrievals = core.Float64Ptr(float64(1))
				postImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				postImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				postImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.PostImportToken(postImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the PostImportTokenOptions model with no property values
				postImportTokenOptionsModelNew := new(ibmkeyprotectapiv2.PostImportTokenOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.PostImportToken(postImportTokenOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke PostImportToken successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the PostImportTokenOptions model
				postImportTokenOptionsModel := new(ibmkeyprotectapiv2.PostImportTokenOptions)
				postImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				postImportTokenOptionsModel.Expiration = core.Float64Ptr(float64(600))
				postImportTokenOptionsModel.MaxAllowedRetrievals = core.Float64Ptr(float64(1))
				postImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				postImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				postImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.PostImportToken(postImportTokenOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetImportToken(getImportTokenOptions *GetImportTokenOptions) - Operation response error`, func() {
		getImportTokenPath := "/api/v2/import_token"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getImportTokenPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetImportToken with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetImportTokenOptions model
				getImportTokenOptionsModel := new(ibmkeyprotectapiv2.GetImportTokenOptions)
				getImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				getImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				getImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				getImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetImportToken(getImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetImportToken(getImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetImportToken(getImportTokenOptions *GetImportTokenOptions)`, func() {
		getImportTokenPath := "/api/v2/import_token"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getImportTokenPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1, "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4=", "nonce": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}`)
				}))
			})
			It(`Invoke GetImportToken successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetImportTokenOptions model
				getImportTokenOptionsModel := new(ibmkeyprotectapiv2.GetImportTokenOptions)
				getImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				getImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				getImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				getImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetImportTokenWithContext(ctx, getImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetImportToken(getImportTokenOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetImportTokenWithContext(ctx, getImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getImportTokenPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "default")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"expiration": 600, "maxAllowedRetrievals": 1, "creationDate": "2000-03-21T00:00:00.000Z", "expirationDate": "2000-03-21T00:00:00.000Z", "remainingRetrievals": 1, "payload": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4=", "nonce": "VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4="}`)
				}))
			})
			It(`Invoke GetImportToken successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetImportToken(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetImportTokenOptions model
				getImportTokenOptionsModel := new(ibmkeyprotectapiv2.GetImportTokenOptions)
				getImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				getImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				getImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				getImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetImportToken(getImportTokenOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetImportToken with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetImportTokenOptions model
				getImportTokenOptionsModel := new(ibmkeyprotectapiv2.GetImportTokenOptions)
				getImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				getImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				getImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				getImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetImportToken(getImportTokenOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetImportTokenOptions model with no property values
				getImportTokenOptionsModelNew := new(ibmkeyprotectapiv2.GetImportTokenOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetImportToken(getImportTokenOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetImportToken successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetImportTokenOptions model
				getImportTokenOptionsModel := new(ibmkeyprotectapiv2.GetImportTokenOptions)
				getImportTokenOptionsModel.BluemixInstance = core.StringPtr("testString")
				getImportTokenOptionsModel.CorrelationID = core.StringPtr("testString")
				getImportTokenOptionsModel.XKmsKeyRing = core.StringPtr("default")
				getImportTokenOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetImportToken(getImportTokenOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetRegistrations(getRegistrationsOptions *GetRegistrationsOptions) - Operation response error`, func() {
		getRegistrationsPath := "/api/v2/keys/testString/registrations"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getRegistrationsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["urlEncodedResourceCRNQuery"]).To(Equal([]string{"crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"}))
					// TODO: Add check for preventKeyDeletion query parameter
					// TODO: Add check for totalCount query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetRegistrations with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetRegistrationsOptions model
				getRegistrationsOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsOptions)
				getRegistrationsOptionsModel.ID = core.StringPtr("testString")
				getRegistrationsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetRegistrations(getRegistrationsOptions *GetRegistrationsOptions)`, func() {
		getRegistrationsPath := "/api/v2/keys/testString/registrations"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getRegistrationsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["urlEncodedResourceCRNQuery"]).To(Equal([]string{"crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"}))
					// TODO: Add check for preventKeyDeletion query parameter
					// TODO: Add check for totalCount query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}`)
				}))
			})
			It(`Invoke GetRegistrations successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetRegistrationsOptions model
				getRegistrationsOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsOptions)
				getRegistrationsOptionsModel.ID = core.StringPtr("testString")
				getRegistrationsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetRegistrationsWithContext(ctx, getRegistrationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetRegistrationsWithContext(ctx, getRegistrationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getRegistrationsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					Expect(req.URL.Query()["urlEncodedResourceCRNQuery"]).To(Equal([]string{"crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"}))
					// TODO: Add check for preventKeyDeletion query parameter
					// TODO: Add check for totalCount query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}`)
				}))
			})
			It(`Invoke GetRegistrations successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrations(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetRegistrationsOptions model
				getRegistrationsOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsOptions)
				getRegistrationsOptionsModel.ID = core.StringPtr("testString")
				getRegistrationsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetRegistrations with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetRegistrationsOptions model
				getRegistrationsOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsOptions)
				getRegistrationsOptionsModel.ID = core.StringPtr("testString")
				getRegistrationsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetRegistrationsOptions model with no property values
				getRegistrationsOptionsModelNew := new(ibmkeyprotectapiv2.GetRegistrationsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetRegistrations successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetRegistrationsOptions model
				getRegistrationsOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsOptions)
				getRegistrationsOptionsModel.ID = core.StringPtr("testString")
				getRegistrationsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrations(getRegistrationsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetRegistrationsAllKeys(getRegistrationsAllKeysOptions *GetRegistrationsAllKeysOptions) - Operation response error`, func() {
		getRegistrationsAllKeysPath := "/api/v2/keys/registrations"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getRegistrationsAllKeysPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["urlEncodedResourceCRNQuery"]).To(Equal([]string{"crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for preventKeyDeletion query parameter
					// TODO: Add check for totalCount query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetRegistrationsAllKeys with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetRegistrationsAllKeysOptions model
				getRegistrationsAllKeysOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions)
				getRegistrationsAllKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsAllKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsAllKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsAllKeysOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetRegistrationsAllKeys(getRegistrationsAllKeysOptions *GetRegistrationsAllKeysOptions)`, func() {
		getRegistrationsAllKeysPath := "/api/v2/keys/registrations"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getRegistrationsAllKeysPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["urlEncodedResourceCRNQuery"]).To(Equal([]string{"crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for preventKeyDeletion query parameter
					// TODO: Add check for totalCount query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}`)
				}))
			})
			It(`Invoke GetRegistrationsAllKeys successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetRegistrationsAllKeysOptions model
				getRegistrationsAllKeysOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions)
				getRegistrationsAllKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsAllKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsAllKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsAllKeysOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetRegistrationsAllKeysWithContext(ctx, getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetRegistrationsAllKeysWithContext(ctx, getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getRegistrationsAllKeysPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["urlEncodedResourceCRNQuery"]).To(Equal([]string{"crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*"}))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(200))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for preventKeyDeletion query parameter
					// TODO: Add check for totalCount query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "keyName": "Example Key Name", "resourceCrn": "crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z", "updatedBy": "IBMid-0000000000", "lastUpdated": "2000-03-21T00:00:00.000Z", "description": "Example description", "registrationMetadata": "us-south", "preventKeyDeletion": false, "keyVersion": {"id": "fadedbee-0000-0000-0000-1234567890ab", "creationDate": "2000-03-21T00:00:00.000Z"}}]}`)
				}))
			})
			It(`Invoke GetRegistrationsAllKeys successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrationsAllKeys(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetRegistrationsAllKeysOptions model
				getRegistrationsAllKeysOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions)
				getRegistrationsAllKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsAllKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsAllKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsAllKeysOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetRegistrationsAllKeys with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetRegistrationsAllKeysOptions model
				getRegistrationsAllKeysOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions)
				getRegistrationsAllKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsAllKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsAllKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsAllKeysOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetRegistrationsAllKeysOptions model with no property values
				getRegistrationsAllKeysOptionsModelNew := new(ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetRegistrationsAllKeys successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetRegistrationsAllKeysOptions model
				getRegistrationsAllKeysOptionsModel := new(ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions)
				getRegistrationsAllKeysOptionsModel.BluemixInstance = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.CorrelationID = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				getRegistrationsAllKeysOptionsModel.UrlEncodedResourceCRNQuery = core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsAllKeysOptionsModel.Limit = core.Int64Ptr(int64(200))
				getRegistrationsAllKeysOptionsModel.Offset = core.Int64Ptr(int64(0))
				getRegistrationsAllKeysOptionsModel.PreventKeyDeletion = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.TotalCount = core.BoolPtr(true)
				getRegistrationsAllKeysOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetRegistrationsAllKeys(getRegistrationsAllKeysOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKeyAlias(createKeyAliasOptions *CreateKeyAliasOptions) - Operation response error`, func() {
		createKeyAliasPath := "/api/v2/keys/testString/aliases/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyAliasPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateKeyAlias with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyAliasOptions model
				createKeyAliasOptionsModel := new(ibmkeyprotectapiv2.CreateKeyAliasOptions)
				createKeyAliasOptionsModel.ID = core.StringPtr("testString")
				createKeyAliasOptionsModel.Alias = core.StringPtr("testString")
				createKeyAliasOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyAliasOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyAliasOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				createKeyAliasOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKeyAlias(createKeyAliasOptions *CreateKeyAliasOptions)`, func() {
		createKeyAliasPath := "/api/v2/keys/testString/aliases/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyAliasPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "alias": "Example-test-key", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke CreateKeyAlias successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the CreateKeyAliasOptions model
				createKeyAliasOptionsModel := new(ibmkeyprotectapiv2.CreateKeyAliasOptions)
				createKeyAliasOptionsModel.ID = core.StringPtr("testString")
				createKeyAliasOptionsModel.Alias = core.StringPtr("testString")
				createKeyAliasOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyAliasOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyAliasOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				createKeyAliasOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.CreateKeyAliasWithContext(ctx, createKeyAliasOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.CreateKeyAliasWithContext(ctx, createKeyAliasOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyAliasPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1}, "resources": [{"keyId": "fadedbee-0000-0000-0000-1234567890ab", "alias": "Example-test-key", "createdBy": "IBMid-0000000000", "creationDate": "2000-03-21T00:00:00.000Z"}]}`)
				}))
			})
			It(`Invoke CreateKeyAlias successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyAlias(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CreateKeyAliasOptions model
				createKeyAliasOptionsModel := new(ibmkeyprotectapiv2.CreateKeyAliasOptions)
				createKeyAliasOptionsModel.ID = core.StringPtr("testString")
				createKeyAliasOptionsModel.Alias = core.StringPtr("testString")
				createKeyAliasOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyAliasOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyAliasOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				createKeyAliasOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateKeyAlias with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyAliasOptions model
				createKeyAliasOptionsModel := new(ibmkeyprotectapiv2.CreateKeyAliasOptions)
				createKeyAliasOptionsModel.ID = core.StringPtr("testString")
				createKeyAliasOptionsModel.Alias = core.StringPtr("testString")
				createKeyAliasOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyAliasOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyAliasOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				createKeyAliasOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateKeyAliasOptions model with no property values
				createKeyAliasOptionsModelNew := new(ibmkeyprotectapiv2.CreateKeyAliasOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke CreateKeyAlias successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyAliasOptions model
				createKeyAliasOptionsModel := new(ibmkeyprotectapiv2.CreateKeyAliasOptions)
				createKeyAliasOptionsModel.ID = core.StringPtr("testString")
				createKeyAliasOptionsModel.Alias = core.StringPtr("testString")
				createKeyAliasOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyAliasOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyAliasOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				createKeyAliasOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.CreateKeyAlias(createKeyAliasOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteKeyAlias(deleteKeyAliasOptions *DeleteKeyAliasOptions)`, func() {
		deleteKeyAliasPath := "/api/v2/keys/testString/aliases/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKeyAliasPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["X-Kms-Key-Ring"]).ToNot(BeNil())
					Expect(req.Header["X-Kms-Key-Ring"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteKeyAlias successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.DeleteKeyAlias(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteKeyAliasOptions model
				deleteKeyAliasOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyAliasOptions)
				deleteKeyAliasOptionsModel.ID = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.Alias = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.DeleteKeyAlias(deleteKeyAliasOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteKeyAlias with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKeyAliasOptions model
				deleteKeyAliasOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyAliasOptions)
				deleteKeyAliasOptionsModel.ID = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.Alias = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.XKmsKeyRing = core.StringPtr("testString")
				deleteKeyAliasOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.DeleteKeyAlias(deleteKeyAliasOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteKeyAliasOptions model with no property values
				deleteKeyAliasOptionsModelNew := new(ibmkeyprotectapiv2.DeleteKeyAliasOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.DeleteKeyAlias(deleteKeyAliasOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListKeyRings(listKeyRingsOptions *ListKeyRingsOptions) - Operation response error`, func() {
		listKeyRingsPath := "/api/v2/key_rings"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listKeyRingsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke ListKeyRings with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the ListKeyRingsOptions model
				listKeyRingsOptionsModel := new(ibmkeyprotectapiv2.ListKeyRingsOptions)
				listKeyRingsOptionsModel.BluemixInstance = core.StringPtr("testString")
				listKeyRingsOptionsModel.Limit = core.Int64Ptr(int64(100))
				listKeyRingsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listKeyRingsOptionsModel.TotalCount = core.BoolPtr(true)
				listKeyRingsOptionsModel.CorrelationID = core.StringPtr("testString")
				listKeyRingsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`ListKeyRings(listKeyRingsOptions *ListKeyRingsOptions)`, func() {
		listKeyRingsPath := "/api/v2/key_rings"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listKeyRingsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "ID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy"}]}`)
				}))
			})
			It(`Invoke ListKeyRings successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the ListKeyRingsOptions model
				listKeyRingsOptionsModel := new(ibmkeyprotectapiv2.ListKeyRingsOptions)
				listKeyRingsOptionsModel.BluemixInstance = core.StringPtr("testString")
				listKeyRingsOptionsModel.Limit = core.Int64Ptr(int64(100))
				listKeyRingsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listKeyRingsOptionsModel.TotalCount = core.BoolPtr(true)
				listKeyRingsOptionsModel.CorrelationID = core.StringPtr("testString")
				listKeyRingsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.ListKeyRingsWithContext(ctx, listKeyRingsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.ListKeyRingsWithContext(ctx, listKeyRingsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(listKeyRingsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "ID", "creationDate": "2000-03-21T00:00:00.000Z", "createdBy": "CreatedBy"}]}`)
				}))
			})
			It(`Invoke ListKeyRings successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.ListKeyRings(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the ListKeyRingsOptions model
				listKeyRingsOptionsModel := new(ibmkeyprotectapiv2.ListKeyRingsOptions)
				listKeyRingsOptionsModel.BluemixInstance = core.StringPtr("testString")
				listKeyRingsOptionsModel.Limit = core.Int64Ptr(int64(100))
				listKeyRingsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listKeyRingsOptionsModel.TotalCount = core.BoolPtr(true)
				listKeyRingsOptionsModel.CorrelationID = core.StringPtr("testString")
				listKeyRingsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke ListKeyRings with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the ListKeyRingsOptions model
				listKeyRingsOptionsModel := new(ibmkeyprotectapiv2.ListKeyRingsOptions)
				listKeyRingsOptionsModel.BluemixInstance = core.StringPtr("testString")
				listKeyRingsOptionsModel.Limit = core.Int64Ptr(int64(100))
				listKeyRingsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listKeyRingsOptionsModel.TotalCount = core.BoolPtr(true)
				listKeyRingsOptionsModel.CorrelationID = core.StringPtr("testString")
				listKeyRingsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the ListKeyRingsOptions model with no property values
				listKeyRingsOptionsModelNew := new(ibmkeyprotectapiv2.ListKeyRingsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke ListKeyRings successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the ListKeyRingsOptions model
				listKeyRingsOptionsModel := new(ibmkeyprotectapiv2.ListKeyRingsOptions)
				listKeyRingsOptionsModel.BluemixInstance = core.StringPtr("testString")
				listKeyRingsOptionsModel.Limit = core.Int64Ptr(int64(100))
				listKeyRingsOptionsModel.Offset = core.Int64Ptr(int64(0))
				listKeyRingsOptionsModel.TotalCount = core.BoolPtr(true)
				listKeyRingsOptionsModel.CorrelationID = core.StringPtr("testString")
				listKeyRingsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.ListKeyRings(listKeyRingsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKeyRing(createKeyRingOptions *CreateKeyRingOptions)`, func() {
		createKeyRingPath := "/api/v2/key_rings/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKeyRingPath))
					Expect(req.Method).To(Equal("POST"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateKeyRing successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.CreateKeyRing(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the CreateKeyRingOptions model
				createKeyRingOptionsModel := new(ibmkeyprotectapiv2.CreateKeyRingOptions)
				createKeyRingOptionsModel.KeyRingID = core.StringPtr("testString")
				createKeyRingOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyRingOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyRingOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.CreateKeyRing(createKeyRingOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke CreateKeyRing with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CreateKeyRingOptions model
				createKeyRingOptionsModel := new(ibmkeyprotectapiv2.CreateKeyRingOptions)
				createKeyRingOptionsModel.KeyRingID = core.StringPtr("testString")
				createKeyRingOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKeyRingOptionsModel.CorrelationID = core.StringPtr("testString")
				createKeyRingOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.CreateKeyRing(createKeyRingOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the CreateKeyRingOptions model with no property values
				createKeyRingOptionsModelNew := new(ibmkeyprotectapiv2.CreateKeyRingOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.CreateKeyRing(createKeyRingOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteKeyRing(deleteKeyRingOptions *DeleteKeyRingOptions)`, func() {
		deleteKeyRingPath := "/api/v2/key_rings/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKeyRingPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// TODO: Add check for force query parameter
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteKeyRing successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.DeleteKeyRing(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteKeyRingOptions model
				deleteKeyRingOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyRingOptions)
				deleteKeyRingOptionsModel.KeyRingID = core.StringPtr("testString")
				deleteKeyRingOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyRingOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyRingOptionsModel.Force = core.BoolPtr(false)
				deleteKeyRingOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.DeleteKeyRing(deleteKeyRingOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteKeyRing with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKeyRingOptions model
				deleteKeyRingOptionsModel := new(ibmkeyprotectapiv2.DeleteKeyRingOptions)
				deleteKeyRingOptionsModel.KeyRingID = core.StringPtr("testString")
				deleteKeyRingOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKeyRingOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKeyRingOptionsModel.Force = core.BoolPtr(false)
				deleteKeyRingOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.DeleteKeyRing(deleteKeyRingOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteKeyRingOptions model with no property values
				deleteKeyRingOptionsModelNew := new(ibmkeyprotectapiv2.DeleteKeyRingOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.DeleteKeyRing(deleteKeyRingOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipAdapters(getKmipAdaptersOptions *GetKmipAdaptersOptions) - Operation response error`, func() {
		getKmipAdaptersPath := "/api/v2/kmip_adapters"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipAdaptersPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					Expect(req.URL.Query()["crk_id"]).To(Equal([]string{"feddecaf-0000-0000-0000-1234567890ab"}))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKmipAdapters with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipAdaptersOptions model
				getKmipAdaptersOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdaptersOptions)
				getKmipAdaptersOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipAdaptersOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipAdaptersOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipAdaptersOptionsModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")
				getKmipAdaptersOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipAdapters(getKmipAdaptersOptions *GetKmipAdaptersOptions)`, func() {
		getKmipAdaptersPath := "/api/v2/kmip_adapters"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipAdaptersPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					Expect(req.URL.Query()["crk_id"]).To(Equal([]string{"feddecaf-0000-0000-0000-1234567890ab"}))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "UpdatedBy", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}`)
				}))
			})
			It(`Invoke GetKmipAdapters successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKmipAdaptersOptions model
				getKmipAdaptersOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdaptersOptions)
				getKmipAdaptersOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipAdaptersOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipAdaptersOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipAdaptersOptionsModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")
				getKmipAdaptersOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKmipAdaptersWithContext(ctx, getKmipAdaptersOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKmipAdaptersWithContext(ctx, getKmipAdaptersOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipAdaptersPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					Expect(req.URL.Query()["crk_id"]).To(Equal([]string{"feddecaf-0000-0000-0000-1234567890ab"}))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "UpdatedBy", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}`)
				}))
			})
			It(`Invoke GetKmipAdapters successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapters(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKmipAdaptersOptions model
				getKmipAdaptersOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdaptersOptions)
				getKmipAdaptersOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipAdaptersOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipAdaptersOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipAdaptersOptionsModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")
				getKmipAdaptersOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKmipAdapters with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipAdaptersOptions model
				getKmipAdaptersOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdaptersOptions)
				getKmipAdaptersOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipAdaptersOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipAdaptersOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipAdaptersOptionsModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")
				getKmipAdaptersOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKmipAdaptersOptions model with no property values
				getKmipAdaptersOptionsModelNew := new(ibmkeyprotectapiv2.GetKmipAdaptersOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKmipAdapters successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipAdaptersOptions model
				getKmipAdaptersOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdaptersOptions)
				getKmipAdaptersOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdaptersOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipAdaptersOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipAdaptersOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipAdaptersOptionsModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")
				getKmipAdaptersOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapters(getKmipAdaptersOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKmipAdapter(createKmipAdapterOptions *CreateKmipAdapterOptions) - Operation response error`, func() {
		createKmipAdapterPath := "/api/v2/kmip_adapters"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKmipAdapterPath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// TODO: Add check for allowExpiringKey query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke CreateKmipAdapter with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KMIPProfileDataBodyKMIPProfileDataNative model
				kmipProfileDataBodyModel := new(ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative)
				kmipProfileDataBodyModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")

				// Construct an instance of the CreateKMIPAdapterObject model
				createKmipAdapterObjectModel := new(ibmkeyprotectapiv2.CreateKMIPAdapterObject)
				createKmipAdapterObjectModel.Name = core.StringPtr("kmip-adapter-name")
				createKmipAdapterObjectModel.Description = core.StringPtr("kmip adapter description")
				createKmipAdapterObjectModel.Profile = core.StringPtr("native_1.0")
				createKmipAdapterObjectModel.ProfileData = kmipProfileDataBodyModel

				// Construct an instance of the CreateKmipAdapterOptions model
				createKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.CreateKmipAdapterOptions)
				createKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKmipAdapterOptionsModel.Metadata = collectionMetadataModel
				createKmipAdapterOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel}
				createKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				createKmipAdapterOptionsModel.AllowExpiringKey = core.BoolPtr(true)
				createKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`CreateKmipAdapter(createKmipAdapterOptions *CreateKmipAdapterOptions)`, func() {
		createKmipAdapterPath := "/api/v2/kmip_adapters"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKmipAdapterPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// TODO: Add check for allowExpiringKey query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "UpdatedBy", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}`)
				}))
			})
			It(`Invoke CreateKmipAdapter successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KMIPProfileDataBodyKMIPProfileDataNative model
				kmipProfileDataBodyModel := new(ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative)
				kmipProfileDataBodyModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")

				// Construct an instance of the CreateKMIPAdapterObject model
				createKmipAdapterObjectModel := new(ibmkeyprotectapiv2.CreateKMIPAdapterObject)
				createKmipAdapterObjectModel.Name = core.StringPtr("kmip-adapter-name")
				createKmipAdapterObjectModel.Description = core.StringPtr("kmip adapter description")
				createKmipAdapterObjectModel.Profile = core.StringPtr("native_1.0")
				createKmipAdapterObjectModel.ProfileData = kmipProfileDataBodyModel

				// Construct an instance of the CreateKmipAdapterOptions model
				createKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.CreateKmipAdapterOptions)
				createKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKmipAdapterOptionsModel.Metadata = collectionMetadataModel
				createKmipAdapterOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel}
				createKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				createKmipAdapterOptionsModel.AllowExpiringKey = core.BoolPtr(true)
				createKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.CreateKmipAdapterWithContext(ctx, createKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.CreateKmipAdapterWithContext(ctx, createKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(createKmipAdapterPath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// TODO: Add check for allowExpiringKey query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "UpdatedBy", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}`)
				}))
			})
			It(`Invoke CreateKmipAdapter successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.CreateKmipAdapter(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KMIPProfileDataBodyKMIPProfileDataNative model
				kmipProfileDataBodyModel := new(ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative)
				kmipProfileDataBodyModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")

				// Construct an instance of the CreateKMIPAdapterObject model
				createKmipAdapterObjectModel := new(ibmkeyprotectapiv2.CreateKMIPAdapterObject)
				createKmipAdapterObjectModel.Name = core.StringPtr("kmip-adapter-name")
				createKmipAdapterObjectModel.Description = core.StringPtr("kmip adapter description")
				createKmipAdapterObjectModel.Profile = core.StringPtr("native_1.0")
				createKmipAdapterObjectModel.ProfileData = kmipProfileDataBodyModel

				// Construct an instance of the CreateKmipAdapterOptions model
				createKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.CreateKmipAdapterOptions)
				createKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKmipAdapterOptionsModel.Metadata = collectionMetadataModel
				createKmipAdapterOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel}
				createKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				createKmipAdapterOptionsModel.AllowExpiringKey = core.BoolPtr(true)
				createKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke CreateKmipAdapter with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KMIPProfileDataBodyKMIPProfileDataNative model
				kmipProfileDataBodyModel := new(ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative)
				kmipProfileDataBodyModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")

				// Construct an instance of the CreateKMIPAdapterObject model
				createKmipAdapterObjectModel := new(ibmkeyprotectapiv2.CreateKMIPAdapterObject)
				createKmipAdapterObjectModel.Name = core.StringPtr("kmip-adapter-name")
				createKmipAdapterObjectModel.Description = core.StringPtr("kmip adapter description")
				createKmipAdapterObjectModel.Profile = core.StringPtr("native_1.0")
				createKmipAdapterObjectModel.ProfileData = kmipProfileDataBodyModel

				// Construct an instance of the CreateKmipAdapterOptions model
				createKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.CreateKmipAdapterOptions)
				createKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKmipAdapterOptionsModel.Metadata = collectionMetadataModel
				createKmipAdapterOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel}
				createKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				createKmipAdapterOptionsModel.AllowExpiringKey = core.BoolPtr(true)
				createKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the CreateKmipAdapterOptions model with no property values
				createKmipAdapterOptionsModelNew := new(ibmkeyprotectapiv2.CreateKmipAdapterOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke CreateKmipAdapter successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the KMIPProfileDataBodyKMIPProfileDataNative model
				kmipProfileDataBodyModel := new(ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative)
				kmipProfileDataBodyModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")

				// Construct an instance of the CreateKMIPAdapterObject model
				createKmipAdapterObjectModel := new(ibmkeyprotectapiv2.CreateKMIPAdapterObject)
				createKmipAdapterObjectModel.Name = core.StringPtr("kmip-adapter-name")
				createKmipAdapterObjectModel.Description = core.StringPtr("kmip adapter description")
				createKmipAdapterObjectModel.Profile = core.StringPtr("native_1.0")
				createKmipAdapterObjectModel.ProfileData = kmipProfileDataBodyModel

				// Construct an instance of the CreateKmipAdapterOptions model
				createKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.CreateKmipAdapterOptions)
				createKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				createKmipAdapterOptionsModel.Metadata = collectionMetadataModel
				createKmipAdapterOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel}
				createKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				createKmipAdapterOptionsModel.AllowExpiringKey = core.BoolPtr(true)
				createKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.CreateKmipAdapter(createKmipAdapterOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipAdapter(getKmipAdapterOptions *GetKmipAdapterOptions) - Operation response error`, func() {
		getKmipAdapterPath := "/api/v2/kmip_adapters/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipAdapterPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKmipAdapter with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipAdapterOptions model
				getKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdapterOptions)
				getKmipAdapterOptionsModel.ID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipAdapter(getKmipAdapterOptions *GetKmipAdapterOptions)`, func() {
		getKmipAdapterPath := "/api/v2/kmip_adapters/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipAdapterPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "UpdatedBy", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}`)
				}))
			})
			It(`Invoke GetKmipAdapter successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKmipAdapterOptions model
				getKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdapterOptions)
				getKmipAdapterOptionsModel.ID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKmipAdapterWithContext(ctx, getKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKmipAdapterWithContext(ctx, getKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipAdapterPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "name": "kmip-adapter-name", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by": "UpdatedBy", "profile": "native_1.0", "description": "kmip adapter description", "profile_data": {"crk_id": "feddecaf-0000-0000-0000-1234567890ab"}}]}`)
				}))
			})
			It(`Invoke GetKmipAdapter successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapter(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKmipAdapterOptions model
				getKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdapterOptions)
				getKmipAdapterOptionsModel.ID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKmipAdapter with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipAdapterOptions model
				getKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdapterOptions)
				getKmipAdapterOptionsModel.ID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKmipAdapterOptions model with no property values
				getKmipAdapterOptionsModelNew := new(ibmkeyprotectapiv2.GetKmipAdapterOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKmipAdapter successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipAdapterOptions model
				getKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.GetKmipAdapterOptions)
				getKmipAdapterOptionsModel.ID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKmipAdapter(getKmipAdapterOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteKmipAdapter(deleteKmipAdapterOptions *DeleteKmipAdapterOptions)`, func() {
		deleteKmipAdapterPath := "/api/v2/kmip_adapters/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKmipAdapterPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteKmipAdapter successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.DeleteKmipAdapter(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteKmipAdapterOptions model
				deleteKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.DeleteKmipAdapterOptions)
				deleteKmipAdapterOptionsModel.ID = core.StringPtr("testString")
				deleteKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.DeleteKmipAdapter(deleteKmipAdapterOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteKmipAdapter with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKmipAdapterOptions model
				deleteKmipAdapterOptionsModel := new(ibmkeyprotectapiv2.DeleteKmipAdapterOptions)
				deleteKmipAdapterOptionsModel.ID = core.StringPtr("testString")
				deleteKmipAdapterOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKmipAdapterOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKmipAdapterOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.DeleteKmipAdapter(deleteKmipAdapterOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteKmipAdapterOptions model with no property values
				deleteKmipAdapterOptionsModelNew := new(ibmkeyprotectapiv2.DeleteKmipAdapterOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.DeleteKmipAdapter(deleteKmipAdapterOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipObjects(getKmipObjectsOptions *GetKmipObjectsOptions) - Operation response error`, func() {
		getKmipObjectsPath := "/api/v2/kmip_adapters/testString/kmip_objects"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipObjectsPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKmipObjects with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipObjectsOptions model
				getKmipObjectsOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectsOptions)
				getKmipObjectsOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipObjectsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipObjectsOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipObjectsOptionsModel.State = []int64{1, 2, 3, 4}
				getKmipObjectsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipObjects(getKmipObjectsOptions *GetKmipObjectsOptions)`, func() {
		getKmipObjectsPath := "/api/v2/kmip_adapters/testString/kmip_objects"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipObjectsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "UpdatedBy", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "DestroyedBy", "recoverable": false}]}`)
				}))
			})
			It(`Invoke GetKmipObjects successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKmipObjectsOptions model
				getKmipObjectsOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectsOptions)
				getKmipObjectsOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipObjectsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipObjectsOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipObjectsOptionsModel.State = []int64{1, 2, 3, 4}
				getKmipObjectsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKmipObjectsWithContext(ctx, getKmipObjectsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKmipObjectsWithContext(ctx, getKmipObjectsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipObjectsPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "UpdatedBy", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "DestroyedBy", "recoverable": false}]}`)
				}))
			})
			It(`Invoke GetKmipObjects successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObjects(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKmipObjectsOptions model
				getKmipObjectsOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectsOptions)
				getKmipObjectsOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipObjectsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipObjectsOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipObjectsOptionsModel.State = []int64{1, 2, 3, 4}
				getKmipObjectsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKmipObjects with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipObjectsOptions model
				getKmipObjectsOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectsOptions)
				getKmipObjectsOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipObjectsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipObjectsOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipObjectsOptionsModel.State = []int64{1, 2, 3, 4}
				getKmipObjectsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKmipObjectsOptions model with no property values
				getKmipObjectsOptionsModelNew := new(ibmkeyprotectapiv2.GetKmipObjectsOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKmipObjects successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipObjectsOptions model
				getKmipObjectsOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectsOptions)
				getKmipObjectsOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipObjectsOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipObjectsOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipObjectsOptionsModel.State = []int64{1, 2, 3, 4}
				getKmipObjectsOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectsOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObjects(getKmipObjectsOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipObject(getKmipObjectOptions *GetKmipObjectOptions) - Operation response error`, func() {
		getKmipObjectPath := "/api/v2/kmip_adapters/testString/kmip_objects/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipObjectPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKmipObject with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipObjectOptions model
				getKmipObjectOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectOptions)
				getKmipObjectOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectOptionsModel.ID = core.StringPtr("testString")
				getKmipObjectOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipObject(getKmipObjectOptions *GetKmipObjectOptions)`, func() {
		getKmipObjectPath := "/api/v2/kmip_adapters/testString/kmip_objects/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipObjectPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "UpdatedBy", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "DestroyedBy", "recoverable": false}]}`)
				}))
			})
			It(`Invoke GetKmipObject successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKmipObjectOptions model
				getKmipObjectOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectOptions)
				getKmipObjectOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectOptionsModel.ID = core.StringPtr("testString")
				getKmipObjectOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKmipObjectWithContext(ctx, getKmipObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKmipObjectWithContext(ctx, getKmipObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipObjectPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"id": "feddecaf-0000-0000-0000-1234567890ab", "kmip_object_type": 2, "state": 1, "created_at": "2019-01-01T12:00:00.000Z", "created_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "created_by": "CreatedBy", "updated_at": "2019-01-01T12:00:00.000Z", "updated_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "updated_by": "UpdatedBy", "destroyed_at": "2019-01-01T12:00:00.000Z", "destroyed_by_kmip_client_cert_id": "feddecaf-0000-0000-0000-1234567890ab", "destroyed_by": "DestroyedBy", "recoverable": false}]}`)
				}))
			})
			It(`Invoke GetKmipObject successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObject(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKmipObjectOptions model
				getKmipObjectOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectOptions)
				getKmipObjectOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectOptionsModel.ID = core.StringPtr("testString")
				getKmipObjectOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKmipObject with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipObjectOptions model
				getKmipObjectOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectOptions)
				getKmipObjectOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectOptionsModel.ID = core.StringPtr("testString")
				getKmipObjectOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKmipObjectOptions model with no property values
				getKmipObjectOptionsModelNew := new(ibmkeyprotectapiv2.GetKmipObjectOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKmipObject successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipObjectOptions model
				getKmipObjectOptionsModel := new(ibmkeyprotectapiv2.GetKmipObjectOptions)
				getKmipObjectOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipObjectOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipObjectOptionsModel.ID = core.StringPtr("testString")
				getKmipObjectOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKmipObject(getKmipObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteKmipObject(deleteKmipObjectOptions *DeleteKmipObjectOptions)`, func() {
		deleteKmipObjectPath := "/api/v2/kmip_adapters/testString/kmip_objects/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKmipObjectPath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// TODO: Add check for force query parameter
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteKmipObject successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.DeleteKmipObject(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteKmipObjectOptions model
				deleteKmipObjectOptionsModel := new(ibmkeyprotectapiv2.DeleteKmipObjectOptions)
				deleteKmipObjectOptionsModel.AdapterID = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.ID = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.Force = core.BoolPtr(false)
				deleteKmipObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.DeleteKmipObject(deleteKmipObjectOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteKmipObject with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKmipObjectOptions model
				deleteKmipObjectOptionsModel := new(ibmkeyprotectapiv2.DeleteKmipObjectOptions)
				deleteKmipObjectOptionsModel.AdapterID = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.ID = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKmipObjectOptionsModel.Force = core.BoolPtr(false)
				deleteKmipObjectOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.DeleteKmipObject(deleteKmipObjectOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteKmipObjectOptions model with no property values
				deleteKmipObjectOptionsModelNew := new(ibmkeyprotectapiv2.DeleteKmipObjectOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.DeleteKmipObject(deleteKmipObjectOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipClientCertificates(getKmipClientCertificatesOptions *GetKmipClientCertificatesOptions) - Operation response error`, func() {
		getKmipClientCertificatesPath := "/api/v2/kmip_adapters/testString/certificates"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipClientCertificatesPath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKmipClientCertificates with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipClientCertificatesOptions model
				getKmipClientCertificatesOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificatesOptions)
				getKmipClientCertificatesOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipClientCertificatesOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipClientCertificatesOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipClientCertificatesOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipClientCertificates(getKmipClientCertificatesOptions *GetKmipClientCertificatesOptions)`, func() {
		getKmipClientCertificatesPath := "/api/v2/kmip_adapters/testString/certificates"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipClientCertificatesPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "Name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy"}]}`)
				}))
			})
			It(`Invoke GetKmipClientCertificates successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKmipClientCertificatesOptions model
				getKmipClientCertificatesOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificatesOptions)
				getKmipClientCertificatesOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipClientCertificatesOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipClientCertificatesOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipClientCertificatesOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKmipClientCertificatesWithContext(ctx, getKmipClientCertificatesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKmipClientCertificatesWithContext(ctx, getKmipClientCertificatesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipClientCertificatesPath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.URL.Query()["limit"]).To(Equal([]string{fmt.Sprint(int64(100))}))
					Expect(req.URL.Query()["offset"]).To(Equal([]string{fmt.Sprint(int64(0))}))
					// TODO: Add check for totalCount query parameter
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "Name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy"}]}`)
				}))
			})
			It(`Invoke GetKmipClientCertificates successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificates(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKmipClientCertificatesOptions model
				getKmipClientCertificatesOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificatesOptions)
				getKmipClientCertificatesOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipClientCertificatesOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipClientCertificatesOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipClientCertificatesOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKmipClientCertificates with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipClientCertificatesOptions model
				getKmipClientCertificatesOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificatesOptions)
				getKmipClientCertificatesOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipClientCertificatesOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipClientCertificatesOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipClientCertificatesOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKmipClientCertificatesOptions model with no property values
				getKmipClientCertificatesOptionsModelNew := new(ibmkeyprotectapiv2.GetKmipClientCertificatesOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKmipClientCertificates successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipClientCertificatesOptions model
				getKmipClientCertificatesOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificatesOptions)
				getKmipClientCertificatesOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Limit = core.Int64Ptr(int64(100))
				getKmipClientCertificatesOptionsModel.Offset = core.Int64Ptr(int64(0))
				getKmipClientCertificatesOptionsModel.TotalCount = core.BoolPtr(true)
				getKmipClientCertificatesOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificatesOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificates(getKmipClientCertificatesOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`AddKmipClientCertificate(addKmipClientCertificateOptions *AddKmipClientCertificateOptions) - Operation response error`, func() {
		addKmipClientCertificatePath := "/api/v2/kmip_adapters/testString/certificates"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(addKmipClientCertificatePath))
					Expect(req.Method).To(Equal("POST"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke AddKmipClientCertificate with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the CreateKMIPClientCertificateObject model
				createKmipClientCertificateObjectModel := new(ibmkeyprotectapiv2.CreateKMIPClientCertificateObject)
				createKmipClientCertificateObjectModel.Certificate = core.StringPtr("testString")
				createKmipClientCertificateObjectModel.Name = core.StringPtr("testString")

				// Construct an instance of the AddKmipClientCertificateOptions model
				addKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.AddKmipClientCertificateOptions)
				addKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Metadata = collectionMetadataModel
				addKmipClientCertificateOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel}
				addKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`AddKmipClientCertificate(addKmipClientCertificateOptions *AddKmipClientCertificateOptions)`, func() {
		addKmipClientCertificatePath := "/api/v2/kmip_adapters/testString/certificates"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(addKmipClientCertificatePath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "Name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "certificate": "Certificate"}]}`)
				}))
			})
			It(`Invoke AddKmipClientCertificate successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the CreateKMIPClientCertificateObject model
				createKmipClientCertificateObjectModel := new(ibmkeyprotectapiv2.CreateKMIPClientCertificateObject)
				createKmipClientCertificateObjectModel.Certificate = core.StringPtr("testString")
				createKmipClientCertificateObjectModel.Name = core.StringPtr("testString")

				// Construct an instance of the AddKmipClientCertificateOptions model
				addKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.AddKmipClientCertificateOptions)
				addKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Metadata = collectionMetadataModel
				addKmipClientCertificateOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel}
				addKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.AddKmipClientCertificateWithContext(ctx, addKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.AddKmipClientCertificateWithContext(ctx, addKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(addKmipClientCertificatePath))
					Expect(req.Method).To(Equal("POST"))

					// For gzip-disabled operation, verify Content-Encoding is not set.
					Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

					// If there is a body, then make sure we can read it
					bodyBuf := new(bytes.Buffer)
					if req.Header.Get("Content-Encoding") == "gzip" {
						body, err := core.NewGzipDecompressionReader(req.Body)
						Expect(err).To(BeNil())
						_, err = bodyBuf.ReadFrom(body)
						Expect(err).To(BeNil())
					} else {
						_, err := bodyBuf.ReadFrom(req.Body)
						Expect(err).To(BeNil())
					}
					fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(201)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "Name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "certificate": "Certificate"}]}`)
				}))
			})
			It(`Invoke AddKmipClientCertificate successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.AddKmipClientCertificate(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the CreateKMIPClientCertificateObject model
				createKmipClientCertificateObjectModel := new(ibmkeyprotectapiv2.CreateKMIPClientCertificateObject)
				createKmipClientCertificateObjectModel.Certificate = core.StringPtr("testString")
				createKmipClientCertificateObjectModel.Name = core.StringPtr("testString")

				// Construct an instance of the AddKmipClientCertificateOptions model
				addKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.AddKmipClientCertificateOptions)
				addKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Metadata = collectionMetadataModel
				addKmipClientCertificateOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel}
				addKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke AddKmipClientCertificate with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the CreateKMIPClientCertificateObject model
				createKmipClientCertificateObjectModel := new(ibmkeyprotectapiv2.CreateKMIPClientCertificateObject)
				createKmipClientCertificateObjectModel.Certificate = core.StringPtr("testString")
				createKmipClientCertificateObjectModel.Name = core.StringPtr("testString")

				// Construct an instance of the AddKmipClientCertificateOptions model
				addKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.AddKmipClientCertificateOptions)
				addKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Metadata = collectionMetadataModel
				addKmipClientCertificateOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel}
				addKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the AddKmipClientCertificateOptions model with no property values
				addKmipClientCertificateOptionsModelNew := new(ibmkeyprotectapiv2.AddKmipClientCertificateOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(201)
				}))
			})
			It(`Invoke AddKmipClientCertificate successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))

				// Construct an instance of the CreateKMIPClientCertificateObject model
				createKmipClientCertificateObjectModel := new(ibmkeyprotectapiv2.CreateKMIPClientCertificateObject)
				createKmipClientCertificateObjectModel.Certificate = core.StringPtr("testString")
				createKmipClientCertificateObjectModel.Name = core.StringPtr("testString")

				// Construct an instance of the AddKmipClientCertificateOptions model
				addKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.AddKmipClientCertificateOptions)
				addKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Metadata = collectionMetadataModel
				addKmipClientCertificateOptionsModel.Resources = []ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel}
				addKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				addKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.AddKmipClientCertificate(addKmipClientCertificateOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipClientCertificate(getKmipClientCertificateOptions *GetKmipClientCertificateOptions) - Operation response error`, func() {
		getKmipClientCertificatePath := "/api/v2/kmip_adapters/testString/certificates/testString"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipClientCertificatePath))
					Expect(req.Method).To(Equal("GET"))
					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetKmipClientCertificate with error: Operation response processing error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipClientCertificateOptions model
				getKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificateOptions)
				getKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.ID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				ibmKeyProtectApiService.EnableRetries(0, 0)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`GetKmipClientCertificate(getKmipClientCertificateOptions *GetKmipClientCertificateOptions)`, func() {
		getKmipClientCertificatePath := "/api/v2/kmip_adapters/testString/certificates/testString"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipClientCertificatePath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "Name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "certificate": "Certificate"}]}`)
				}))
			})
			It(`Invoke GetKmipClientCertificate successfully with retries`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())
				ibmKeyProtectApiService.EnableRetries(0, 0)

				// Construct an instance of the GetKmipClientCertificateOptions model
				getKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificateOptions)
				getKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.ID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := ibmKeyProtectApiService.GetKmipClientCertificateWithContext(ctx, getKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				ibmKeyProtectApiService.DisableRetries()
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = ibmKeyProtectApiService.GetKmipClientCertificateWithContext(ctx, getKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getKmipClientCertificatePath))
					Expect(req.Method).To(Equal("GET"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"metadata": {"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json", "collectionTotal": 1, "totalCount": 1}, "resources": [{"name": "Name", "id": "feddecaf-0000-0000-0000-1234567890ab", "created_at": "2019-01-01T12:00:00.000Z", "created_by": "CreatedBy", "certificate": "Certificate"}]}`)
				}))
			})
			It(`Invoke GetKmipClientCertificate successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificate(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetKmipClientCertificateOptions model
				getKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificateOptions)
				getKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.ID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetKmipClientCertificate with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipClientCertificateOptions model
				getKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificateOptions)
				getKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.ID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
				// Construct a second instance of the GetKmipClientCertificateOptions model with no property values
				getKmipClientCertificateOptionsModelNew := new(ibmkeyprotectapiv2.GetKmipClientCertificateOptions)
				// Invoke operation with invalid model (negative test)
				result, response, operationErr = ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetKmipClientCertificate successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the GetKmipClientCertificateOptions model
				getKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.GetKmipClientCertificateOptions)
				getKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.ID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				getKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := ibmKeyProtectApiService.GetKmipClientCertificate(getKmipClientCertificateOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`DeleteKmipClientCertificate(deleteKmipClientCertificateOptions *DeleteKmipClientCertificateOptions)`, func() {
		deleteKmipClientCertificatePath := "/api/v2/kmip_adapters/testString/certificates/testString"
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(deleteKmipClientCertificatePath))
					Expect(req.Method).To(Equal("DELETE"))

					Expect(req.Header["Bluemix-Instance"]).ToNot(BeNil())
					Expect(req.Header["Bluemix-Instance"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					Expect(req.Header["Correlation-Id"]).ToNot(BeNil())
					Expect(req.Header["Correlation-Id"][0]).To(Equal(fmt.Sprintf("%v", "testString")))
					res.WriteHeader(204)
				}))
			})
			It(`Invoke DeleteKmipClientCertificate successfully`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				response, operationErr := ibmKeyProtectApiService.DeleteKmipClientCertificate(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())

				// Construct an instance of the DeleteKmipClientCertificateOptions model
				deleteKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.DeleteKmipClientCertificateOptions)
				deleteKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.ID = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				response, operationErr = ibmKeyProtectApiService.DeleteKmipClientCertificate(deleteKmipClientCertificateOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
			})
			It(`Invoke DeleteKmipClientCertificate with error: Operation validation and request error`, func() {
				ibmKeyProtectApiService, serviceErr := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(ibmKeyProtectApiService).ToNot(BeNil())

				// Construct an instance of the DeleteKmipClientCertificateOptions model
				deleteKmipClientCertificateOptionsModel := new(ibmkeyprotectapiv2.DeleteKmipClientCertificateOptions)
				deleteKmipClientCertificateOptionsModel.AdapterID = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.ID = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.BluemixInstance = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.CorrelationID = core.StringPtr("testString")
				deleteKmipClientCertificateOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := ibmKeyProtectApiService.SetServiceURL("")
				Expect(err).To(BeNil())
				response, operationErr := ibmKeyProtectApiService.DeleteKmipClientCertificate(deleteKmipClientCertificateOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				// Construct a second instance of the DeleteKmipClientCertificateOptions model with no property values
				deleteKmipClientCertificateOptionsModelNew := new(ibmkeyprotectapiv2.DeleteKmipClientCertificateOptions)
				// Invoke operation with invalid model (negative test)
				response, operationErr = ibmKeyProtectApiService.DeleteKmipClientCertificate(deleteKmipClientCertificateOptionsModelNew)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Model constructor tests`, func() {
		Context(`Using a service client instance`, func() {
			ibmKeyProtectApiService, _ := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{
				URL:           "http://ibmkeyprotectapiv2modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It(`Invoke NewActionOnKeyOptions successfully`, func() {
				// Construct an instance of the ActionOnKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				action := "disable"
				keyActionBody := CreateMockReader("This is a mock file.")
				actionOnKeyOptionsModel := ibmKeyProtectApiService.NewActionOnKeyOptions(id, bluemixInstance, action, keyActionBody)
				actionOnKeyOptionsModel.SetID("testString")
				actionOnKeyOptionsModel.SetBluemixInstance("testString")
				actionOnKeyOptionsModel.SetAction("disable")
				actionOnKeyOptionsModel.SetKeyActionBody(CreateMockReader("This is a mock file."))
				actionOnKeyOptionsModel.SetCorrelationID("testString")
				actionOnKeyOptionsModel.SetXKmsKeyRing("testString")
				actionOnKeyOptionsModel.SetPrefer("return=representation")
				actionOnKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(actionOnKeyOptionsModel).ToNot(BeNil())
				Expect(actionOnKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(actionOnKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(actionOnKeyOptionsModel.Action).To(Equal(core.StringPtr("disable")))
				Expect(actionOnKeyOptionsModel.KeyActionBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(actionOnKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(actionOnKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(actionOnKeyOptionsModel.Prefer).To(Equal(core.StringPtr("return=representation")))
				Expect(actionOnKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewAddKmipClientCertificateOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.kms.kmip_client_certificate+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the CreateKMIPClientCertificateObject model
				createKmipClientCertificateObjectModel := new(ibmkeyprotectapiv2.CreateKMIPClientCertificateObject)
				Expect(createKmipClientCertificateObjectModel).ToNot(BeNil())
				createKmipClientCertificateObjectModel.Certificate = core.StringPtr("testString")
				createKmipClientCertificateObjectModel.Name = core.StringPtr("testString")
				Expect(createKmipClientCertificateObjectModel.Certificate).To(Equal(core.StringPtr("testString")))
				Expect(createKmipClientCertificateObjectModel.Name).To(Equal(core.StringPtr("testString")))

				// Construct an instance of the AddKmipClientCertificateOptions model
				adapterID := "testString"
				bluemixInstance := "testString"
				var addKmipClientCertificateOptionsMetadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				addKmipClientCertificateOptionsResources := []ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{}
				addKmipClientCertificateOptionsModel := ibmKeyProtectApiService.NewAddKmipClientCertificateOptions(adapterID, bluemixInstance, addKmipClientCertificateOptionsMetadata, addKmipClientCertificateOptionsResources)
				addKmipClientCertificateOptionsModel.SetAdapterID("testString")
				addKmipClientCertificateOptionsModel.SetBluemixInstance("testString")
				addKmipClientCertificateOptionsModel.SetMetadata(collectionMetadataModel)
				addKmipClientCertificateOptionsModel.SetResources([]ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel})
				addKmipClientCertificateOptionsModel.SetCorrelationID("testString")
				addKmipClientCertificateOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(addKmipClientCertificateOptionsModel).ToNot(BeNil())
				Expect(addKmipClientCertificateOptionsModel.AdapterID).To(Equal(core.StringPtr("testString")))
				Expect(addKmipClientCertificateOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(addKmipClientCertificateOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(addKmipClientCertificateOptionsModel.Resources).To(Equal([]ibmkeyprotectapiv2.CreateKMIPClientCertificateObject{*createKmipClientCertificateObjectModel}))
				Expect(addKmipClientCertificateOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(addKmipClientCertificateOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCollectionMetadata successfully`, func() {
				collectionType := "application/vnd.ibm.kms.allowed_ip_metadata+json"
				collectionTotal := int64(1)
				_model, err := ibmKeyProtectApiService.NewCollectionMetadata(collectionType, collectionTotal)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCreateKMIPAdapterObject successfully`, func() {
				profile := "native_1.0"
				_model, err := ibmKeyProtectApiService.NewCreateKMIPAdapterObject(profile)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCreateKMIPClientCertificateObject successfully`, func() {
				certificate := "testString"
				_model, err := ibmKeyProtectApiService.NewCreateKMIPClientCertificateObject(certificate)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewCreateKeyAliasOptions successfully`, func() {
				// Construct an instance of the CreateKeyAliasOptions model
				id := "testString"
				alias := "testString"
				bluemixInstance := "testString"
				createKeyAliasOptionsModel := ibmKeyProtectApiService.NewCreateKeyAliasOptions(id, alias, bluemixInstance)
				createKeyAliasOptionsModel.SetID("testString")
				createKeyAliasOptionsModel.SetAlias("testString")
				createKeyAliasOptionsModel.SetBluemixInstance("testString")
				createKeyAliasOptionsModel.SetCorrelationID("testString")
				createKeyAliasOptionsModel.SetXKmsKeyRing("testString")
				createKeyAliasOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createKeyAliasOptionsModel).ToNot(BeNil())
				Expect(createKeyAliasOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(createKeyAliasOptionsModel.Alias).To(Equal(core.StringPtr("testString")))
				Expect(createKeyAliasOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(createKeyAliasOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(createKeyAliasOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(createKeyAliasOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateKeyOptions successfully`, func() {
				// Construct an instance of the CreateKeyOptions model
				bluemixInstance := "testString"
				keyCreateBody := CreateMockReader("This is a mock file.")
				createKeyOptionsModel := ibmKeyProtectApiService.NewCreateKeyOptions(bluemixInstance, keyCreateBody)
				createKeyOptionsModel.SetBluemixInstance("testString")
				createKeyOptionsModel.SetKeyCreateBody(CreateMockReader("This is a mock file."))
				createKeyOptionsModel.SetCorrelationID("testString")
				createKeyOptionsModel.SetPrefer("return=representation")
				createKeyOptionsModel.SetXKmsKeyRing("default")
				createKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createKeyOptionsModel).ToNot(BeNil())
				Expect(createKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(createKeyOptionsModel.KeyCreateBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(createKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(createKeyOptionsModel.Prefer).To(Equal(core.StringPtr("return=representation")))
				Expect(createKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("default")))
				Expect(createKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateKeyRingOptions successfully`, func() {
				// Construct an instance of the CreateKeyRingOptions model
				keyRingID := "testString"
				bluemixInstance := "testString"
				createKeyRingOptionsModel := ibmKeyProtectApiService.NewCreateKeyRingOptions(keyRingID, bluemixInstance)
				createKeyRingOptionsModel.SetKeyRingID("testString")
				createKeyRingOptionsModel.SetBluemixInstance("testString")
				createKeyRingOptionsModel.SetCorrelationID("testString")
				createKeyRingOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createKeyRingOptionsModel).ToNot(BeNil())
				Expect(createKeyRingOptionsModel.KeyRingID).To(Equal(core.StringPtr("testString")))
				Expect(createKeyRingOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(createKeyRingOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(createKeyRingOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateKeyWithPoliciesOverridesOptions successfully`, func() {
				// Construct an instance of the CreateKeyWithPoliciesOverridesOptions model
				bluemixInstance := "testString"
				keyWithPolicyOverridesCreateBody := CreateMockReader("This is a mock file.")
				createKeyWithPoliciesOverridesOptionsModel := ibmKeyProtectApiService.NewCreateKeyWithPoliciesOverridesOptions(bluemixInstance, keyWithPolicyOverridesCreateBody)
				createKeyWithPoliciesOverridesOptionsModel.SetBluemixInstance("testString")
				createKeyWithPoliciesOverridesOptionsModel.SetKeyWithPolicyOverridesCreateBody(CreateMockReader("This is a mock file."))
				createKeyWithPoliciesOverridesOptionsModel.SetCorrelationID("testString")
				createKeyWithPoliciesOverridesOptionsModel.SetPrefer("return=representation")
				createKeyWithPoliciesOverridesOptionsModel.SetXKmsKeyRing("default")
				createKeyWithPoliciesOverridesOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createKeyWithPoliciesOverridesOptionsModel).ToNot(BeNil())
				Expect(createKeyWithPoliciesOverridesOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(createKeyWithPoliciesOverridesOptionsModel.KeyWithPolicyOverridesCreateBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(createKeyWithPoliciesOverridesOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(createKeyWithPoliciesOverridesOptionsModel.Prefer).To(Equal(core.StringPtr("return=representation")))
				Expect(createKeyWithPoliciesOverridesOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("default")))
				Expect(createKeyWithPoliciesOverridesOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewCreateKmipAdapterOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.kms.kmip_adapter+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the KMIPProfileDataBodyKMIPProfileDataNative model
				kmipProfileDataBodyModel := new(ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative)
				Expect(kmipProfileDataBodyModel).ToNot(BeNil())
				kmipProfileDataBodyModel.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")
				Expect(kmipProfileDataBodyModel.CrkID).To(Equal(core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")))

				// Construct an instance of the CreateKMIPAdapterObject model
				createKmipAdapterObjectModel := new(ibmkeyprotectapiv2.CreateKMIPAdapterObject)
				Expect(createKmipAdapterObjectModel).ToNot(BeNil())
				createKmipAdapterObjectModel.Name = core.StringPtr("kmip-adapter-name")
				createKmipAdapterObjectModel.Description = core.StringPtr("kmip adapter description")
				createKmipAdapterObjectModel.Profile = core.StringPtr("native_1.0")
				createKmipAdapterObjectModel.ProfileData = kmipProfileDataBodyModel
				Expect(createKmipAdapterObjectModel.Name).To(Equal(core.StringPtr("kmip-adapter-name")))
				Expect(createKmipAdapterObjectModel.Description).To(Equal(core.StringPtr("kmip adapter description")))
				Expect(createKmipAdapterObjectModel.Profile).To(Equal(core.StringPtr("native_1.0")))
				Expect(createKmipAdapterObjectModel.ProfileData).To(Equal(kmipProfileDataBodyModel))

				// Construct an instance of the CreateKmipAdapterOptions model
				bluemixInstance := "testString"
				var createKmipAdapterOptionsMetadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				createKmipAdapterOptionsResources := []ibmkeyprotectapiv2.CreateKMIPAdapterObject{}
				createKmipAdapterOptionsModel := ibmKeyProtectApiService.NewCreateKmipAdapterOptions(bluemixInstance, createKmipAdapterOptionsMetadata, createKmipAdapterOptionsResources)
				createKmipAdapterOptionsModel.SetBluemixInstance("testString")
				createKmipAdapterOptionsModel.SetMetadata(collectionMetadataModel)
				createKmipAdapterOptionsModel.SetResources([]ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel})
				createKmipAdapterOptionsModel.SetCorrelationID("testString")
				createKmipAdapterOptionsModel.SetAllowExpiringKey(true)
				createKmipAdapterOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(createKmipAdapterOptionsModel).ToNot(BeNil())
				Expect(createKmipAdapterOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(createKmipAdapterOptionsModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(createKmipAdapterOptionsModel.Resources).To(Equal([]ibmkeyprotectapiv2.CreateKMIPAdapterObject{*createKmipAdapterObjectModel}))
				Expect(createKmipAdapterOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(createKmipAdapterOptionsModel.AllowExpiringKey).To(Equal(core.BoolPtr(true)))
				Expect(createKmipAdapterOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteKeyAliasOptions successfully`, func() {
				// Construct an instance of the DeleteKeyAliasOptions model
				id := "testString"
				alias := "testString"
				bluemixInstance := "testString"
				deleteKeyAliasOptionsModel := ibmKeyProtectApiService.NewDeleteKeyAliasOptions(id, alias, bluemixInstance)
				deleteKeyAliasOptionsModel.SetID("testString")
				deleteKeyAliasOptionsModel.SetAlias("testString")
				deleteKeyAliasOptionsModel.SetBluemixInstance("testString")
				deleteKeyAliasOptionsModel.SetCorrelationID("testString")
				deleteKeyAliasOptionsModel.SetXKmsKeyRing("testString")
				deleteKeyAliasOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteKeyAliasOptionsModel).ToNot(BeNil())
				Expect(deleteKeyAliasOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyAliasOptionsModel.Alias).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyAliasOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyAliasOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyAliasOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyAliasOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteKeyOptions successfully`, func() {
				// Construct an instance of the DeleteKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				deleteKeyOptionsModel := ibmKeyProtectApiService.NewDeleteKeyOptions(id, bluemixInstance)
				deleteKeyOptionsModel.SetID("testString")
				deleteKeyOptionsModel.SetBluemixInstance("testString")
				deleteKeyOptionsModel.SetCorrelationID("testString")
				deleteKeyOptionsModel.SetXKmsKeyRing("testString")
				deleteKeyOptionsModel.SetPrefer("return=representation")
				deleteKeyOptionsModel.SetForce(false)
				deleteKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteKeyOptionsModel).ToNot(BeNil())
				Expect(deleteKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyOptionsModel.Prefer).To(Equal(core.StringPtr("return=representation")))
				Expect(deleteKeyOptionsModel.Force).To(Equal(core.BoolPtr(false)))
				Expect(deleteKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteKeyRingOptions successfully`, func() {
				// Construct an instance of the DeleteKeyRingOptions model
				keyRingID := "testString"
				bluemixInstance := "testString"
				deleteKeyRingOptionsModel := ibmKeyProtectApiService.NewDeleteKeyRingOptions(keyRingID, bluemixInstance)
				deleteKeyRingOptionsModel.SetKeyRingID("testString")
				deleteKeyRingOptionsModel.SetBluemixInstance("testString")
				deleteKeyRingOptionsModel.SetCorrelationID("testString")
				deleteKeyRingOptionsModel.SetForce(false)
				deleteKeyRingOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteKeyRingOptionsModel).ToNot(BeNil())
				Expect(deleteKeyRingOptionsModel.KeyRingID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyRingOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyRingOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKeyRingOptionsModel.Force).To(Equal(core.BoolPtr(false)))
				Expect(deleteKeyRingOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteKmipAdapterOptions successfully`, func() {
				// Construct an instance of the DeleteKmipAdapterOptions model
				id := "testString"
				bluemixInstance := "testString"
				deleteKmipAdapterOptionsModel := ibmKeyProtectApiService.NewDeleteKmipAdapterOptions(id, bluemixInstance)
				deleteKmipAdapterOptionsModel.SetID("testString")
				deleteKmipAdapterOptionsModel.SetBluemixInstance("testString")
				deleteKmipAdapterOptionsModel.SetCorrelationID("testString")
				deleteKmipAdapterOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteKmipAdapterOptionsModel).ToNot(BeNil())
				Expect(deleteKmipAdapterOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipAdapterOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipAdapterOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipAdapterOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteKmipClientCertificateOptions successfully`, func() {
				// Construct an instance of the DeleteKmipClientCertificateOptions model
				adapterID := "testString"
				id := "testString"
				bluemixInstance := "testString"
				deleteKmipClientCertificateOptionsModel := ibmKeyProtectApiService.NewDeleteKmipClientCertificateOptions(adapterID, id, bluemixInstance)
				deleteKmipClientCertificateOptionsModel.SetAdapterID("testString")
				deleteKmipClientCertificateOptionsModel.SetID("testString")
				deleteKmipClientCertificateOptionsModel.SetBluemixInstance("testString")
				deleteKmipClientCertificateOptionsModel.SetCorrelationID("testString")
				deleteKmipClientCertificateOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteKmipClientCertificateOptionsModel).ToNot(BeNil())
				Expect(deleteKmipClientCertificateOptionsModel.AdapterID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipClientCertificateOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipClientCertificateOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipClientCertificateOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipClientCertificateOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDeleteKmipObjectOptions successfully`, func() {
				// Construct an instance of the DeleteKmipObjectOptions model
				adapterID := "testString"
				bluemixInstance := "testString"
				id := "testString"
				deleteKmipObjectOptionsModel := ibmKeyProtectApiService.NewDeleteKmipObjectOptions(adapterID, bluemixInstance, id)
				deleteKmipObjectOptionsModel.SetAdapterID("testString")
				deleteKmipObjectOptionsModel.SetBluemixInstance("testString")
				deleteKmipObjectOptionsModel.SetID("testString")
				deleteKmipObjectOptionsModel.SetCorrelationID("testString")
				deleteKmipObjectOptionsModel.SetForce(false)
				deleteKmipObjectOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(deleteKmipObjectOptionsModel).ToNot(BeNil())
				Expect(deleteKmipObjectOptionsModel.AdapterID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipObjectOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipObjectOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipObjectOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(deleteKmipObjectOptionsModel.Force).To(Equal(core.BoolPtr(false)))
				Expect(deleteKmipObjectOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDisableKeyOptions successfully`, func() {
				// Construct an instance of the DisableKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				disableKeyOptionsModel := ibmKeyProtectApiService.NewDisableKeyOptions(id, bluemixInstance)
				disableKeyOptionsModel.SetID("testString")
				disableKeyOptionsModel.SetBluemixInstance("testString")
				disableKeyOptionsModel.SetCorrelationID("testString")
				disableKeyOptionsModel.SetXKmsKeyRing("testString")
				disableKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(disableKeyOptionsModel).ToNot(BeNil())
				Expect(disableKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(disableKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(disableKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(disableKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(disableKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewDualAuthDeleteProperties successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewDualAuthDeleteProperties(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewEnableKeyOptions successfully`, func() {
				// Construct an instance of the EnableKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				enableKeyOptionsModel := ibmKeyProtectApiService.NewEnableKeyOptions(id, bluemixInstance)
				enableKeyOptionsModel.SetID("testString")
				enableKeyOptionsModel.SetBluemixInstance("testString")
				enableKeyOptionsModel.SetCorrelationID("testString")
				enableKeyOptionsModel.SetXKmsKeyRing("testString")
				enableKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(enableKeyOptionsModel).ToNot(BeNil())
				Expect(enableKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(enableKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(enableKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(enableKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(enableKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetAllowedIPPortOptions successfully`, func() {
				// Construct an instance of the GetAllowedIPPortOptions model
				bluemixInstance := "testString"
				getAllowedIpPortOptionsModel := ibmKeyProtectApiService.NewGetAllowedIPPortOptions(bluemixInstance)
				getAllowedIpPortOptionsModel.SetBluemixInstance("testString")
				getAllowedIpPortOptionsModel.SetCorrelationID("testString")
				getAllowedIpPortOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getAllowedIpPortOptionsModel).ToNot(BeNil())
				Expect(getAllowedIpPortOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getAllowedIpPortOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getAllowedIpPortOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetImportTokenOptions successfully`, func() {
				// Construct an instance of the GetImportTokenOptions model
				bluemixInstance := "testString"
				getImportTokenOptionsModel := ibmKeyProtectApiService.NewGetImportTokenOptions(bluemixInstance)
				getImportTokenOptionsModel.SetBluemixInstance("testString")
				getImportTokenOptionsModel.SetCorrelationID("testString")
				getImportTokenOptionsModel.SetXKmsKeyRing("default")
				getImportTokenOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getImportTokenOptionsModel).ToNot(BeNil())
				Expect(getImportTokenOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getImportTokenOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getImportTokenOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("default")))
				Expect(getImportTokenOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetInstancePolicyOptions successfully`, func() {
				// Construct an instance of the GetInstancePolicyOptions model
				bluemixInstance := "testString"
				getInstancePolicyOptionsModel := ibmKeyProtectApiService.NewGetInstancePolicyOptions(bluemixInstance)
				getInstancePolicyOptionsModel.SetBluemixInstance("testString")
				getInstancePolicyOptionsModel.SetCorrelationID("testString")
				getInstancePolicyOptionsModel.SetPolicy("allowedNetwork")
				getInstancePolicyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getInstancePolicyOptionsModel).ToNot(BeNil())
				Expect(getInstancePolicyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getInstancePolicyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getInstancePolicyOptionsModel.Policy).To(Equal(core.StringPtr("allowedNetwork")))
				Expect(getInstancePolicyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKeyCollectionMetadataOptions successfully`, func() {
				// Construct an instance of the GetKeyCollectionMetadataOptions model
				bluemixInstance := "testString"
				getKeyCollectionMetadataOptionsModel := ibmKeyProtectApiService.NewGetKeyCollectionMetadataOptions(bluemixInstance)
				getKeyCollectionMetadataOptionsModel.SetBluemixInstance("testString")
				getKeyCollectionMetadataOptionsModel.SetCorrelationID("testString")
				getKeyCollectionMetadataOptionsModel.SetState([]int64{0, 1, 2, 3})
				getKeyCollectionMetadataOptionsModel.SetExtractable(true)
				getKeyCollectionMetadataOptionsModel.SetFilter("testString")
				getKeyCollectionMetadataOptionsModel.SetXKmsKeyRing("testString")
				getKeyCollectionMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKeyCollectionMetadataOptionsModel).ToNot(BeNil())
				Expect(getKeyCollectionMetadataOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKeyCollectionMetadataOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKeyCollectionMetadataOptionsModel.State).To(Equal([]int64{0, 1, 2, 3}))
				Expect(getKeyCollectionMetadataOptionsModel.Extractable).To(Equal(core.BoolPtr(true)))
				Expect(getKeyCollectionMetadataOptionsModel.Filter).To(Equal(core.StringPtr("testString")))
				Expect(getKeyCollectionMetadataOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getKeyCollectionMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKeyMetadataOptions successfully`, func() {
				// Construct an instance of the GetKeyMetadataOptions model
				id := "testString"
				bluemixInstance := "testString"
				getKeyMetadataOptionsModel := ibmKeyProtectApiService.NewGetKeyMetadataOptions(id, bluemixInstance)
				getKeyMetadataOptionsModel.SetID("testString")
				getKeyMetadataOptionsModel.SetBluemixInstance("testString")
				getKeyMetadataOptionsModel.SetCorrelationID("testString")
				getKeyMetadataOptionsModel.SetXKmsKeyRing("testString")
				getKeyMetadataOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKeyMetadataOptionsModel).ToNot(BeNil())
				Expect(getKeyMetadataOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getKeyMetadataOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKeyMetadataOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKeyMetadataOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getKeyMetadataOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKeyOptions successfully`, func() {
				// Construct an instance of the GetKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				getKeyOptionsModel := ibmKeyProtectApiService.NewGetKeyOptions(id, bluemixInstance)
				getKeyOptionsModel.SetID("testString")
				getKeyOptionsModel.SetBluemixInstance("testString")
				getKeyOptionsModel.SetCorrelationID("testString")
				getKeyOptionsModel.SetXKmsKeyRing("testString")
				getKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKeyOptionsModel).ToNot(BeNil())
				Expect(getKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKeyVersionsOptions successfully`, func() {
				// Construct an instance of the GetKeyVersionsOptions model
				id := "testString"
				bluemixInstance := "testString"
				getKeyVersionsOptionsModel := ibmKeyProtectApiService.NewGetKeyVersionsOptions(id, bluemixInstance)
				getKeyVersionsOptionsModel.SetID("testString")
				getKeyVersionsOptionsModel.SetBluemixInstance("testString")
				getKeyVersionsOptionsModel.SetCorrelationID("testString")
				getKeyVersionsOptionsModel.SetXKmsKeyRing("testString")
				getKeyVersionsOptionsModel.SetLimit(int64(200))
				getKeyVersionsOptionsModel.SetOffset(int64(0))
				getKeyVersionsOptionsModel.SetTotalCount(true)
				getKeyVersionsOptionsModel.SetAllKeyStates(false)
				getKeyVersionsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKeyVersionsOptionsModel).ToNot(BeNil())
				Expect(getKeyVersionsOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getKeyVersionsOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKeyVersionsOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKeyVersionsOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getKeyVersionsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(200))))
				Expect(getKeyVersionsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getKeyVersionsOptionsModel.TotalCount).To(Equal(core.BoolPtr(true)))
				Expect(getKeyVersionsOptionsModel.AllKeyStates).To(Equal(core.BoolPtr(false)))
				Expect(getKeyVersionsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKeysOptions successfully`, func() {
				// Construct an instance of the GetKeysOptions model
				bluemixInstance := "testString"
				getKeysOptionsModel := ibmKeyProtectApiService.NewGetKeysOptions(bluemixInstance)
				getKeysOptionsModel.SetBluemixInstance("testString")
				getKeysOptionsModel.SetCorrelationID("testString")
				getKeysOptionsModel.SetLimit(int64(200))
				getKeysOptionsModel.SetOffset(int64(0))
				getKeysOptionsModel.SetState([]int64{0, 1, 2, 3})
				getKeysOptionsModel.SetExtractable(true)
				getKeysOptionsModel.SetSearch("testString")
				getKeysOptionsModel.SetSort("id")
				getKeysOptionsModel.SetFilter("testString")
				getKeysOptionsModel.SetXKmsKeyRing("testString")
				getKeysOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKeysOptionsModel).ToNot(BeNil())
				Expect(getKeysOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKeysOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKeysOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(200))))
				Expect(getKeysOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getKeysOptionsModel.State).To(Equal([]int64{0, 1, 2, 3}))
				Expect(getKeysOptionsModel.Extractable).To(Equal(core.BoolPtr(true)))
				Expect(getKeysOptionsModel.Search).To(Equal(core.StringPtr("testString")))
				Expect(getKeysOptionsModel.Sort).To(Equal(core.StringPtr("id")))
				Expect(getKeysOptionsModel.Filter).To(Equal(core.StringPtr("testString")))
				Expect(getKeysOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getKeysOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKmipAdapterOptions successfully`, func() {
				// Construct an instance of the GetKmipAdapterOptions model
				id := "testString"
				bluemixInstance := "testString"
				getKmipAdapterOptionsModel := ibmKeyProtectApiService.NewGetKmipAdapterOptions(id, bluemixInstance)
				getKmipAdapterOptionsModel.SetID("testString")
				getKmipAdapterOptionsModel.SetBluemixInstance("testString")
				getKmipAdapterOptionsModel.SetCorrelationID("testString")
				getKmipAdapterOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKmipAdapterOptionsModel).ToNot(BeNil())
				Expect(getKmipAdapterOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipAdapterOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKmipAdapterOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipAdapterOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKmipAdaptersOptions successfully`, func() {
				// Construct an instance of the GetKmipAdaptersOptions model
				bluemixInstance := "testString"
				getKmipAdaptersOptionsModel := ibmKeyProtectApiService.NewGetKmipAdaptersOptions(bluemixInstance)
				getKmipAdaptersOptionsModel.SetBluemixInstance("testString")
				getKmipAdaptersOptionsModel.SetCorrelationID("testString")
				getKmipAdaptersOptionsModel.SetLimit(int64(100))
				getKmipAdaptersOptionsModel.SetOffset(int64(0))
				getKmipAdaptersOptionsModel.SetTotalCount(true)
				getKmipAdaptersOptionsModel.SetCrkID("feddecaf-0000-0000-0000-1234567890ab")
				getKmipAdaptersOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKmipAdaptersOptionsModel).ToNot(BeNil())
				Expect(getKmipAdaptersOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKmipAdaptersOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipAdaptersOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(100))))
				Expect(getKmipAdaptersOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getKmipAdaptersOptionsModel.TotalCount).To(Equal(core.BoolPtr(true)))
				Expect(getKmipAdaptersOptionsModel.CrkID).To(Equal(core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")))
				Expect(getKmipAdaptersOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKmipClientCertificateOptions successfully`, func() {
				// Construct an instance of the GetKmipClientCertificateOptions model
				adapterID := "testString"
				id := "testString"
				bluemixInstance := "testString"
				getKmipClientCertificateOptionsModel := ibmKeyProtectApiService.NewGetKmipClientCertificateOptions(adapterID, id, bluemixInstance)
				getKmipClientCertificateOptionsModel.SetAdapterID("testString")
				getKmipClientCertificateOptionsModel.SetID("testString")
				getKmipClientCertificateOptionsModel.SetBluemixInstance("testString")
				getKmipClientCertificateOptionsModel.SetCorrelationID("testString")
				getKmipClientCertificateOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKmipClientCertificateOptionsModel).ToNot(BeNil())
				Expect(getKmipClientCertificateOptionsModel.AdapterID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipClientCertificateOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipClientCertificateOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKmipClientCertificateOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipClientCertificateOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKmipClientCertificatesOptions successfully`, func() {
				// Construct an instance of the GetKmipClientCertificatesOptions model
				adapterID := "testString"
				bluemixInstance := "testString"
				getKmipClientCertificatesOptionsModel := ibmKeyProtectApiService.NewGetKmipClientCertificatesOptions(adapterID, bluemixInstance)
				getKmipClientCertificatesOptionsModel.SetAdapterID("testString")
				getKmipClientCertificatesOptionsModel.SetBluemixInstance("testString")
				getKmipClientCertificatesOptionsModel.SetLimit(int64(100))
				getKmipClientCertificatesOptionsModel.SetOffset(int64(0))
				getKmipClientCertificatesOptionsModel.SetTotalCount(true)
				getKmipClientCertificatesOptionsModel.SetCorrelationID("testString")
				getKmipClientCertificatesOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKmipClientCertificatesOptionsModel).ToNot(BeNil())
				Expect(getKmipClientCertificatesOptionsModel.AdapterID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipClientCertificatesOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKmipClientCertificatesOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(100))))
				Expect(getKmipClientCertificatesOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getKmipClientCertificatesOptionsModel.TotalCount).To(Equal(core.BoolPtr(true)))
				Expect(getKmipClientCertificatesOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipClientCertificatesOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKmipObjectOptions successfully`, func() {
				// Construct an instance of the GetKmipObjectOptions model
				adapterID := "testString"
				bluemixInstance := "testString"
				id := "testString"
				getKmipObjectOptionsModel := ibmKeyProtectApiService.NewGetKmipObjectOptions(adapterID, bluemixInstance, id)
				getKmipObjectOptionsModel.SetAdapterID("testString")
				getKmipObjectOptionsModel.SetBluemixInstance("testString")
				getKmipObjectOptionsModel.SetID("testString")
				getKmipObjectOptionsModel.SetCorrelationID("testString")
				getKmipObjectOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKmipObjectOptionsModel).ToNot(BeNil())
				Expect(getKmipObjectOptionsModel.AdapterID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipObjectOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKmipObjectOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipObjectOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipObjectOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetKmipObjectsOptions successfully`, func() {
				// Construct an instance of the GetKmipObjectsOptions model
				adapterID := "testString"
				bluemixInstance := "testString"
				getKmipObjectsOptionsModel := ibmKeyProtectApiService.NewGetKmipObjectsOptions(adapterID, bluemixInstance)
				getKmipObjectsOptionsModel.SetAdapterID("testString")
				getKmipObjectsOptionsModel.SetBluemixInstance("testString")
				getKmipObjectsOptionsModel.SetLimit(int64(100))
				getKmipObjectsOptionsModel.SetOffset(int64(0))
				getKmipObjectsOptionsModel.SetTotalCount(true)
				getKmipObjectsOptionsModel.SetState([]int64{1, 2, 3, 4})
				getKmipObjectsOptionsModel.SetCorrelationID("testString")
				getKmipObjectsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getKmipObjectsOptionsModel).ToNot(BeNil())
				Expect(getKmipObjectsOptionsModel.AdapterID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipObjectsOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getKmipObjectsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(100))))
				Expect(getKmipObjectsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getKmipObjectsOptionsModel.TotalCount).To(Equal(core.BoolPtr(true)))
				Expect(getKmipObjectsOptionsModel.State).To(Equal([]int64{1, 2, 3, 4}))
				Expect(getKmipObjectsOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getKmipObjectsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetPolicyOptions successfully`, func() {
				// Construct an instance of the GetPolicyOptions model
				id := "testString"
				bluemixInstance := "testString"
				getPolicyOptionsModel := ibmKeyProtectApiService.NewGetPolicyOptions(id, bluemixInstance)
				getPolicyOptionsModel.SetID("testString")
				getPolicyOptionsModel.SetBluemixInstance("testString")
				getPolicyOptionsModel.SetCorrelationID("testString")
				getPolicyOptionsModel.SetXKmsKeyRing("testString")
				getPolicyOptionsModel.SetPolicy("dualAuthDelete")
				getPolicyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getPolicyOptionsModel).ToNot(BeNil())
				Expect(getPolicyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getPolicyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getPolicyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getPolicyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getPolicyOptionsModel.Policy).To(Equal(core.StringPtr("dualAuthDelete")))
				Expect(getPolicyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetRegistrationsAllKeysOptions successfully`, func() {
				// Construct an instance of the GetRegistrationsAllKeysOptions model
				bluemixInstance := "testString"
				getRegistrationsAllKeysOptionsModel := ibmKeyProtectApiService.NewGetRegistrationsAllKeysOptions(bluemixInstance)
				getRegistrationsAllKeysOptionsModel.SetBluemixInstance("testString")
				getRegistrationsAllKeysOptionsModel.SetCorrelationID("testString")
				getRegistrationsAllKeysOptionsModel.SetXKmsKeyRing("testString")
				getRegistrationsAllKeysOptionsModel.SetUrlEncodedResourceCRNQuery("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsAllKeysOptionsModel.SetLimit(int64(200))
				getRegistrationsAllKeysOptionsModel.SetOffset(int64(0))
				getRegistrationsAllKeysOptionsModel.SetPreventKeyDeletion(true)
				getRegistrationsAllKeysOptionsModel.SetTotalCount(true)
				getRegistrationsAllKeysOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getRegistrationsAllKeysOptionsModel).ToNot(BeNil())
				Expect(getRegistrationsAllKeysOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getRegistrationsAllKeysOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getRegistrationsAllKeysOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getRegistrationsAllKeysOptionsModel.UrlEncodedResourceCRNQuery).To(Equal(core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")))
				Expect(getRegistrationsAllKeysOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(200))))
				Expect(getRegistrationsAllKeysOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getRegistrationsAllKeysOptionsModel.PreventKeyDeletion).To(Equal(core.BoolPtr(true)))
				Expect(getRegistrationsAllKeysOptionsModel.TotalCount).To(Equal(core.BoolPtr(true)))
				Expect(getRegistrationsAllKeysOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewGetRegistrationsOptions successfully`, func() {
				// Construct an instance of the GetRegistrationsOptions model
				id := "testString"
				bluemixInstance := "testString"
				getRegistrationsOptionsModel := ibmKeyProtectApiService.NewGetRegistrationsOptions(id, bluemixInstance)
				getRegistrationsOptionsModel.SetID("testString")
				getRegistrationsOptionsModel.SetBluemixInstance("testString")
				getRegistrationsOptionsModel.SetCorrelationID("testString")
				getRegistrationsOptionsModel.SetXKmsKeyRing("testString")
				getRegistrationsOptionsModel.SetLimit(int64(200))
				getRegistrationsOptionsModel.SetOffset(int64(0))
				getRegistrationsOptionsModel.SetUrlEncodedResourceCRNQuery("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")
				getRegistrationsOptionsModel.SetPreventKeyDeletion(true)
				getRegistrationsOptionsModel.SetTotalCount(true)
				getRegistrationsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(getRegistrationsOptionsModel).ToNot(BeNil())
				Expect(getRegistrationsOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(getRegistrationsOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(getRegistrationsOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(getRegistrationsOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(getRegistrationsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(200))))
				Expect(getRegistrationsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(getRegistrationsOptionsModel.UrlEncodedResourceCRNQuery).To(Equal(core.StringPtr("crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*")))
				Expect(getRegistrationsOptionsModel.PreventKeyDeletion).To(Equal(core.BoolPtr(true)))
				Expect(getRegistrationsOptionsModel.TotalCount).To(Equal(core.BoolPtr(true)))
				Expect(getRegistrationsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewInstancePolicyAllowedIPPolicyData successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewInstancePolicyAllowedIPPolicyData(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewInstancePolicyAllowedNetworkPolicyData successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewInstancePolicyAllowedNetworkPolicyData(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewInstancePolicyAllowedNetworkPolicyDataAttributes successfully`, func() {
				allowedNetwork := "public-and-private"
				_model, err := ibmKeyProtectApiService.NewInstancePolicyAllowedNetworkPolicyDataAttributes(allowedNetwork)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewInstancePolicyKeyCreateImportAccessPolicyData successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewInstancePolicyKeyCreateImportAccessPolicyData(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewInstancePolicyRotationPolicyData successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewInstancePolicyRotationPolicyData(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewKeyPolicyDualAuthDelete successfully`, func() {
				typeVar := "application/vnd.ibm.kms.policy+json"
				var dualAuthDelete *ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete = nil
				_, err := ibmKeyProtectApiService.NewKeyPolicyDualAuthDelete(typeVar, dualAuthDelete)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewKeyPolicyDualAuthDeleteDualAuthDelete successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewKeyPolicyDualAuthDeleteDualAuthDelete(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewKeyPolicyRotation successfully`, func() {
				typeVar := "application/vnd.ibm.kms.policy+json"
				var rotation *ibmkeyprotectapiv2.KeyPolicyRotationRotation = nil
				_, err := ibmKeyProtectApiService.NewKeyPolicyRotation(typeVar, rotation)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewKeyPolicyRotationRotation successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewKeyPolicyRotationRotation(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewListKeyRingsOptions successfully`, func() {
				// Construct an instance of the ListKeyRingsOptions model
				bluemixInstance := "testString"
				listKeyRingsOptionsModel := ibmKeyProtectApiService.NewListKeyRingsOptions(bluemixInstance)
				listKeyRingsOptionsModel.SetBluemixInstance("testString")
				listKeyRingsOptionsModel.SetLimit(int64(100))
				listKeyRingsOptionsModel.SetOffset(int64(0))
				listKeyRingsOptionsModel.SetTotalCount(true)
				listKeyRingsOptionsModel.SetCorrelationID("testString")
				listKeyRingsOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(listKeyRingsOptionsModel).ToNot(BeNil())
				Expect(listKeyRingsOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(listKeyRingsOptionsModel.Limit).To(Equal(core.Int64Ptr(int64(100))))
				Expect(listKeyRingsOptionsModel.Offset).To(Equal(core.Int64Ptr(int64(0))))
				Expect(listKeyRingsOptionsModel.TotalCount).To(Equal(core.BoolPtr(true)))
				Expect(listKeyRingsOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(listKeyRingsOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewMetricsProperties successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewMetricsProperties(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewPatchKeyOptions successfully`, func() {
				// Construct an instance of the PatchKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				patchKeyOptionsModel := ibmKeyProtectApiService.NewPatchKeyOptions(id, bluemixInstance)
				patchKeyOptionsModel.SetID("testString")
				patchKeyOptionsModel.SetBluemixInstance("testString")
				patchKeyOptionsModel.SetKeyPatchBody(CreateMockReader("This is a mock file."))
				patchKeyOptionsModel.SetCorrelationID("testString")
				patchKeyOptionsModel.SetXKmsKeyRing("testString")
				patchKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(patchKeyOptionsModel).ToNot(BeNil())
				Expect(patchKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(patchKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(patchKeyOptionsModel.KeyPatchBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(patchKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(patchKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(patchKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPostImportTokenOptions successfully`, func() {
				// Construct an instance of the PostImportTokenOptions model
				bluemixInstance := "testString"
				postImportTokenOptionsModel := ibmKeyProtectApiService.NewPostImportTokenOptions(bluemixInstance)
				postImportTokenOptionsModel.SetBluemixInstance("testString")
				postImportTokenOptionsModel.SetExpiration(float64(600))
				postImportTokenOptionsModel.SetMaxAllowedRetrievals(float64(1))
				postImportTokenOptionsModel.SetCorrelationID("testString")
				postImportTokenOptionsModel.SetXKmsKeyRing("default")
				postImportTokenOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(postImportTokenOptionsModel).ToNot(BeNil())
				Expect(postImportTokenOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(postImportTokenOptionsModel.Expiration).To(Equal(core.Float64Ptr(float64(600))))
				Expect(postImportTokenOptionsModel.MaxAllowedRetrievals).To(Equal(core.Float64Ptr(float64(1))))
				Expect(postImportTokenOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(postImportTokenOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("default")))
				Expect(postImportTokenOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPurgeKeyOptions successfully`, func() {
				// Construct an instance of the PurgeKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				purgeKeyOptionsModel := ibmKeyProtectApiService.NewPurgeKeyOptions(id, bluemixInstance)
				purgeKeyOptionsModel.SetID("testString")
				purgeKeyOptionsModel.SetBluemixInstance("testString")
				purgeKeyOptionsModel.SetCorrelationID("testString")
				purgeKeyOptionsModel.SetXKmsKeyRing("testString")
				purgeKeyOptionsModel.SetPrefer("return=representation")
				purgeKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(purgeKeyOptionsModel).ToNot(BeNil())
				Expect(purgeKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(purgeKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(purgeKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(purgeKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(purgeKeyOptionsModel.Prefer).To(Equal(core.StringPtr("return=representation")))
				Expect(purgeKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPutInstancePolicyOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.allowed_ip_metadata+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.kms.allowed_ip_metadata+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the InstancePolicyAllowedNetworkPolicyDataAttributes model
				instancePolicyAllowedNetworkPolicyDataAttributesModel := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyDataAttributes)
				Expect(instancePolicyAllowedNetworkPolicyDataAttributesModel).ToNot(BeNil())
				instancePolicyAllowedNetworkPolicyDataAttributesModel.AllowedNetwork = core.StringPtr("public-and-private")
				Expect(instancePolicyAllowedNetworkPolicyDataAttributesModel.AllowedNetwork).To(Equal(core.StringPtr("public-and-private")))

				// Construct an instance of the InstancePolicyAllowedNetworkPolicyData model
				instancePolicyAllowedNetworkPolicyDataModel := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData)
				Expect(instancePolicyAllowedNetworkPolicyDataModel).ToNot(BeNil())
				instancePolicyAllowedNetworkPolicyDataModel.Enabled = core.BoolPtr(true)
				instancePolicyAllowedNetworkPolicyDataModel.Attributes = instancePolicyAllowedNetworkPolicyDataAttributesModel
				Expect(instancePolicyAllowedNetworkPolicyDataModel.Enabled).To(Equal(core.BoolPtr(true)))
				Expect(instancePolicyAllowedNetworkPolicyDataModel.Attributes).To(Equal(instancePolicyAllowedNetworkPolicyDataAttributesModel))

				// Construct an instance of the SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem model
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem)
				Expect(setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel).ToNot(BeNil())
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyType = core.StringPtr("allowedNetwork")
				setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyData = instancePolicyAllowedNetworkPolicyDataModel
				Expect(setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyType).To(Equal(core.StringPtr("allowedNetwork")))
				Expect(setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel.PolicyData).To(Equal(instancePolicyAllowedNetworkPolicyDataModel))

				// Construct an instance of the SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork model
				setInstancePoliciesOneOfModel := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork)
				Expect(setInstancePoliciesOneOfModel).ToNot(BeNil())
				setInstancePoliciesOneOfModel.Metadata = collectionMetadataModel
				setInstancePoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem{*setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel}
				Expect(setInstancePoliciesOneOfModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(setInstancePoliciesOneOfModel.Resources).To(Equal([]ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem{*setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel}))

				// Construct an instance of the PutInstancePolicyOptions model
				bluemixInstance := "testString"
				var instancePolicyPutBody ibmkeyprotectapiv2.SetInstancePoliciesOneOfIntf = nil
				putInstancePolicyOptionsModel := ibmKeyProtectApiService.NewPutInstancePolicyOptions(bluemixInstance, instancePolicyPutBody)
				putInstancePolicyOptionsModel.SetBluemixInstance("testString")
				putInstancePolicyOptionsModel.SetInstancePolicyPutBody(setInstancePoliciesOneOfModel)
				putInstancePolicyOptionsModel.SetCorrelationID("testString")
				putInstancePolicyOptionsModel.SetPolicy("allowedNetwork")
				putInstancePolicyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(putInstancePolicyOptionsModel).ToNot(BeNil())
				Expect(putInstancePolicyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(putInstancePolicyOptionsModel.InstancePolicyPutBody).To(Equal(setInstancePoliciesOneOfModel))
				Expect(putInstancePolicyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(putInstancePolicyOptionsModel.Policy).To(Equal(core.StringPtr("allowedNetwork")))
				Expect(putInstancePolicyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewPutPolicyOptions successfully`, func() {
				// Construct an instance of the CollectionMetadata model
				collectionMetadataModel := new(ibmkeyprotectapiv2.CollectionMetadata)
				Expect(collectionMetadataModel).ToNot(BeNil())
				collectionMetadataModel.CollectionType = core.StringPtr("application/vnd.ibm.kms.allowed_ip_metadata+json")
				collectionMetadataModel.CollectionTotal = core.Int64Ptr(int64(1))
				Expect(collectionMetadataModel.CollectionType).To(Equal(core.StringPtr("application/vnd.ibm.kms.allowed_ip_metadata+json")))
				Expect(collectionMetadataModel.CollectionTotal).To(Equal(core.Int64Ptr(int64(1))))

				// Construct an instance of the KeyPolicyDualAuthDeleteDualAuthDelete model
				keyPolicyDualAuthDeleteDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete)
				Expect(keyPolicyDualAuthDeleteDualAuthDeleteModel).ToNot(BeNil())
				keyPolicyDualAuthDeleteDualAuthDeleteModel.Enabled = core.BoolPtr(true)
				Expect(keyPolicyDualAuthDeleteDualAuthDeleteModel.Enabled).To(Equal(core.BoolPtr(true)))

				// Construct an instance of the KeyPolicyDualAuthDelete model
				keyPolicyDualAuthDeleteModel := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDelete)
				Expect(keyPolicyDualAuthDeleteModel).ToNot(BeNil())
				keyPolicyDualAuthDeleteModel.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
				keyPolicyDualAuthDeleteModel.DualAuthDelete = keyPolicyDualAuthDeleteDualAuthDeleteModel
				Expect(keyPolicyDualAuthDeleteModel.Type).To(Equal(core.StringPtr("application/vnd.ibm.kms.policy+json")))
				Expect(keyPolicyDualAuthDeleteModel.DualAuthDelete).To(Equal(keyPolicyDualAuthDeleteDualAuthDeleteModel))

				// Construct an instance of the SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete model
				setKeyPoliciesOneOfModel := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete)
				Expect(setKeyPoliciesOneOfModel).ToNot(BeNil())
				setKeyPoliciesOneOfModel.Metadata = collectionMetadataModel
				setKeyPoliciesOneOfModel.Resources = []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel}
				Expect(setKeyPoliciesOneOfModel.Metadata).To(Equal(collectionMetadataModel))
				Expect(setKeyPoliciesOneOfModel.Resources).To(Equal([]ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{*keyPolicyDualAuthDeleteModel}))

				// Construct an instance of the PutPolicyOptions model
				id := "testString"
				bluemixInstance := "testString"
				var keyPolicyPutBody ibmkeyprotectapiv2.SetKeyPoliciesOneOfIntf = nil
				putPolicyOptionsModel := ibmKeyProtectApiService.NewPutPolicyOptions(id, bluemixInstance, keyPolicyPutBody)
				putPolicyOptionsModel.SetID("testString")
				putPolicyOptionsModel.SetBluemixInstance("testString")
				putPolicyOptionsModel.SetKeyPolicyPutBody(setKeyPoliciesOneOfModel)
				putPolicyOptionsModel.SetCorrelationID("testString")
				putPolicyOptionsModel.SetXKmsKeyRing("testString")
				putPolicyOptionsModel.SetPolicy("dualAuthDelete")
				putPolicyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(putPolicyOptionsModel).ToNot(BeNil())
				Expect(putPolicyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(putPolicyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(putPolicyOptionsModel.KeyPolicyPutBody).To(Equal(setKeyPoliciesOneOfModel))
				Expect(putPolicyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(putPolicyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(putPolicyOptionsModel.Policy).To(Equal(core.StringPtr("dualAuthDelete")))
				Expect(putPolicyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRestoreKeyOptions successfully`, func() {
				// Construct an instance of the RestoreKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				restoreKeyOptionsModel := ibmKeyProtectApiService.NewRestoreKeyOptions(id, bluemixInstance)
				restoreKeyOptionsModel.SetID("testString")
				restoreKeyOptionsModel.SetBluemixInstance("testString")
				restoreKeyOptionsModel.SetCorrelationID("testString")
				restoreKeyOptionsModel.SetXKmsKeyRing("testString")
				restoreKeyOptionsModel.SetPrefer("return=representation")
				restoreKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(restoreKeyOptionsModel).ToNot(BeNil())
				Expect(restoreKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(restoreKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(restoreKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(restoreKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(restoreKeyOptionsModel.Prefer).To(Equal(core.StringPtr("return=representation")))
				Expect(restoreKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRewrapKeyOptions successfully`, func() {
				// Construct an instance of the RewrapKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				keyActionRewrapBody := CreateMockReader("This is a mock file.")
				rewrapKeyOptionsModel := ibmKeyProtectApiService.NewRewrapKeyOptions(id, bluemixInstance, keyActionRewrapBody)
				rewrapKeyOptionsModel.SetID("testString")
				rewrapKeyOptionsModel.SetBluemixInstance("testString")
				rewrapKeyOptionsModel.SetKeyActionRewrapBody(CreateMockReader("This is a mock file."))
				rewrapKeyOptionsModel.SetCorrelationID("testString")
				rewrapKeyOptionsModel.SetXKmsKeyRing("testString")
				rewrapKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(rewrapKeyOptionsModel).ToNot(BeNil())
				Expect(rewrapKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(rewrapKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(rewrapKeyOptionsModel.KeyActionRewrapBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(rewrapKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(rewrapKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(rewrapKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewRotateKeyOptions successfully`, func() {
				// Construct an instance of the RotateKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				rotateKeyOptionsModel := ibmKeyProtectApiService.NewRotateKeyOptions(id, bluemixInstance)
				rotateKeyOptionsModel.SetID("testString")
				rotateKeyOptionsModel.SetBluemixInstance("testString")
				rotateKeyOptionsModel.SetKeyActionRotateBody(CreateMockReader("This is a mock file."))
				rotateKeyOptionsModel.SetCorrelationID("testString")
				rotateKeyOptionsModel.SetXKmsKeyRing("testString")
				rotateKeyOptionsModel.SetPrefer("return=representation")
				rotateKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(rotateKeyOptionsModel).ToNot(BeNil())
				Expect(rotateKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(rotateKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(rotateKeyOptionsModel.KeyActionRotateBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(rotateKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(rotateKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(rotateKeyOptionsModel.Prefer).To(Equal(core.StringPtr("return=representation")))
				Expect(rotateKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewSetInstancePoliciesOneOfResourcesItem successfully`, func() {
				policyType := "allowedNetwork"
				var policyData *ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData = nil
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem successfully`, func() {
				policyType := "allowedIP"
				var policyData *ibmkeyprotectapiv2.InstancePolicyAllowedIPPolicyData = nil
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem successfully`, func() {
				policyType := "allowedNetwork"
				var policyData *ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData = nil
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem successfully`, func() {
				policyType := "keyCreateImportAccess"
				var policyData *ibmkeyprotectapiv2.InstancePolicyKeyCreateImportAccessPolicyData = nil
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem successfully`, func() {
				policyType := "metrics"
				var policyData *ibmkeyprotectapiv2.MetricsProperties = nil
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem successfully`, func() {
				policyType := "rotation"
				var policyData *ibmkeyprotectapiv2.InstancePolicyRotationPolicyData = nil
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePolicyDualAuthDeleteResourcesItem successfully`, func() {
				policyType := "dualAuthDelete"
				var policyData *ibmkeyprotectapiv2.DualAuthDeleteProperties = nil
				_, err := ibmKeyProtectApiService.NewSetInstancePolicyDualAuthDeleteResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetKeyForDeletionOptions successfully`, func() {
				// Construct an instance of the SetKeyForDeletionOptions model
				id := "testString"
				bluemixInstance := "testString"
				setKeyForDeletionOptionsModel := ibmKeyProtectApiService.NewSetKeyForDeletionOptions(id, bluemixInstance)
				setKeyForDeletionOptionsModel.SetID("testString")
				setKeyForDeletionOptionsModel.SetBluemixInstance("testString")
				setKeyForDeletionOptionsModel.SetCorrelationID("testString")
				setKeyForDeletionOptionsModel.SetXKmsKeyRing("testString")
				setKeyForDeletionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(setKeyForDeletionOptionsModel).ToNot(BeNil())
				Expect(setKeyForDeletionOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(setKeyForDeletionOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(setKeyForDeletionOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(setKeyForDeletionOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(setKeyForDeletionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewSetMultipleInstancePoliciesResourcesItem successfully`, func() {
				policyType := "allowedNetwork"
				var policyData *ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItemPolicyData = nil
				_, err := ibmKeyProtectApiService.NewSetMultipleInstancePoliciesResourcesItem(policyType, policyData)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetMultipleInstancePoliciesResourcesItemPolicyData successfully`, func() {
				enabled := true
				_model, err := ibmKeyProtectApiService.NewSetMultipleInstancePoliciesResourcesItemPolicyData(enabled)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSetMultipleKeyPoliciesResource successfully`, func() {
				typeVar := "application/vnd.ibm.kms.policy+json"
				var dualAuthDelete *ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete = nil
				var rotation *ibmkeyprotectapiv2.KeyPolicyRotationRotation = nil
				_, err := ibmKeyProtectApiService.NewSetMultipleKeyPoliciesResource(typeVar, dualAuthDelete, rotation)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSyncAssociatedResourcesOptions successfully`, func() {
				// Construct an instance of the SyncAssociatedResourcesOptions model
				id := "testString"
				bluemixInstance := "testString"
				syncAssociatedResourcesOptionsModel := ibmKeyProtectApiService.NewSyncAssociatedResourcesOptions(id, bluemixInstance)
				syncAssociatedResourcesOptionsModel.SetID("testString")
				syncAssociatedResourcesOptionsModel.SetBluemixInstance("testString")
				syncAssociatedResourcesOptionsModel.SetCorrelationID("testString")
				syncAssociatedResourcesOptionsModel.SetXKmsKeyRing("testString")
				syncAssociatedResourcesOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(syncAssociatedResourcesOptionsModel).ToNot(BeNil())
				Expect(syncAssociatedResourcesOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(syncAssociatedResourcesOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(syncAssociatedResourcesOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(syncAssociatedResourcesOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(syncAssociatedResourcesOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUnsetKeyForDeletionOptions successfully`, func() {
				// Construct an instance of the UnsetKeyForDeletionOptions model
				id := "testString"
				bluemixInstance := "testString"
				unsetKeyForDeletionOptionsModel := ibmKeyProtectApiService.NewUnsetKeyForDeletionOptions(id, bluemixInstance)
				unsetKeyForDeletionOptionsModel.SetID("testString")
				unsetKeyForDeletionOptionsModel.SetBluemixInstance("testString")
				unsetKeyForDeletionOptionsModel.SetCorrelationID("testString")
				unsetKeyForDeletionOptionsModel.SetXKmsKeyRing("testString")
				unsetKeyForDeletionOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(unsetKeyForDeletionOptionsModel).ToNot(BeNil())
				Expect(unsetKeyForDeletionOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(unsetKeyForDeletionOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(unsetKeyForDeletionOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(unsetKeyForDeletionOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(unsetKeyForDeletionOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewUnwrapKeyOptions successfully`, func() {
				// Construct an instance of the UnwrapKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				keyActionUnwrapBody := CreateMockReader("This is a mock file.")
				unwrapKeyOptionsModel := ibmKeyProtectApiService.NewUnwrapKeyOptions(id, bluemixInstance, keyActionUnwrapBody)
				unwrapKeyOptionsModel.SetID("testString")
				unwrapKeyOptionsModel.SetBluemixInstance("testString")
				unwrapKeyOptionsModel.SetKeyActionUnwrapBody(CreateMockReader("This is a mock file."))
				unwrapKeyOptionsModel.SetCorrelationID("testString")
				unwrapKeyOptionsModel.SetXKmsKeyRing("testString")
				unwrapKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(unwrapKeyOptionsModel).ToNot(BeNil())
				Expect(unwrapKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(unwrapKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(unwrapKeyOptionsModel.KeyActionUnwrapBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(unwrapKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(unwrapKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(unwrapKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewWrapKeyOptions successfully`, func() {
				// Construct an instance of the WrapKeyOptions model
				id := "testString"
				bluemixInstance := "testString"
				wrapKeyOptionsModel := ibmKeyProtectApiService.NewWrapKeyOptions(id, bluemixInstance)
				wrapKeyOptionsModel.SetID("testString")
				wrapKeyOptionsModel.SetBluemixInstance("testString")
				wrapKeyOptionsModel.SetKeyActionWrapBody(CreateMockReader("This is a mock file."))
				wrapKeyOptionsModel.SetCorrelationID("testString")
				wrapKeyOptionsModel.SetXKmsKeyRing("testString")
				wrapKeyOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(wrapKeyOptionsModel).ToNot(BeNil())
				Expect(wrapKeyOptionsModel.ID).To(Equal(core.StringPtr("testString")))
				Expect(wrapKeyOptionsModel.BluemixInstance).To(Equal(core.StringPtr("testString")))
				Expect(wrapKeyOptionsModel.KeyActionWrapBody).To(Equal(CreateMockReader("This is a mock file.")))
				Expect(wrapKeyOptionsModel.CorrelationID).To(Equal(core.StringPtr("testString")))
				Expect(wrapKeyOptionsModel.XKmsKeyRing).To(Equal(core.StringPtr("testString")))
				Expect(wrapKeyOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
			It(`Invoke NewKMIPProfileDataBodyKMIPProfileDataNative successfully`, func() {
				crkID := "feddecaf-0000-0000-0000-1234567890ab"
				_model, err := ibmKeyProtectApiService.NewKMIPProfileDataBodyKMIPProfileDataNative(crkID)
				Expect(_model).ToNot(BeNil())
				Expect(err).To(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyAllowedIP successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem{}
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyAllowedIP(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem{}
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetInstancePolicyDualAuthDeleteResourcesItem{}
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem{}
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyMetrics successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem{}
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyMetrics(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetInstancePolicyRotation successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem{}
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetInstancePolicyRotation(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetInstancePoliciesOneOfSetMultipleInstancePolicies successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItem{}
				_, err := ibmKeyProtectApiService.NewSetInstancePoliciesOneOfSetMultipleInstancePolicies(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.KeyPolicyDualAuthDelete{}
				_, err := ibmKeyProtectApiService.NewSetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetKeyPoliciesOneOfSetKeyPolicyRotation successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.KeyPolicyRotation{}
				_, err := ibmKeyProtectApiService.NewSetKeyPoliciesOneOfSetKeyPolicyRotation(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
			It(`Invoke NewSetKeyPoliciesOneOfSetMultipleKeyPolicies successfully`, func() {
				var metadata *ibmkeyprotectapiv2.CollectionMetadata = nil
				resources := []ibmkeyprotectapiv2.SetMultipleKeyPoliciesResource{}
				_, err := ibmKeyProtectApiService.NewSetKeyPoliciesOneOfSetMultipleKeyPolicies(metadata, resources)
				Expect(err).ToNot(BeNil())
			})
		})
	})
	Describe(`Model unmarshaling tests`, func() {
		It(`Invoke UnmarshalCollectionMetadata successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.CollectionMetadata)
			model.CollectionType = core.StringPtr("application/vnd.ibm.kms.allowed_ip_metadata+json")
			model.CollectionTotal = core.Int64Ptr(int64(1))

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.CollectionMetadata
			err = ibmkeyprotectapiv2.UnmarshalCollectionMetadata(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalCreateKMIPAdapterObject successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.CreateKMIPAdapterObject)
			model.Name = core.StringPtr("kmip-adapter-name")
			model.Description = core.StringPtr("kmip adapter description")
			model.Profile = core.StringPtr("native_1.0")
			model.ProfileData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.CreateKMIPAdapterObject
			err = ibmkeyprotectapiv2.UnmarshalCreateKMIPAdapterObject(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalCreateKMIPClientCertificateObject successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.CreateKMIPClientCertificateObject)
			model.Certificate = core.StringPtr("testString")
			model.Name = core.StringPtr("testString")

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.CreateKMIPClientCertificateObject
			err = ibmkeyprotectapiv2.UnmarshalCreateKMIPClientCertificateObject(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalDualAuthDeleteProperties successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.DualAuthDeleteProperties)
			model.Enabled = core.BoolPtr(true)

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.DualAuthDeleteProperties
			err = ibmkeyprotectapiv2.UnmarshalDualAuthDeleteProperties(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalImportToken successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.ImportToken)
			model.Expiration = core.Float64Ptr(float64(600))
			model.MaxAllowedRetrievals = core.Float64Ptr(float64(1))
			model.CreationDate = CreateMockDateTime("2000-03-21T00:00:00.000Z")
			model.ExpirationDate = CreateMockDateTime("2000-03-21T00:00:00.000Z")
			model.RemainingRetrievals = core.Float64Ptr(float64(1))

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.ImportToken
			err = ibmkeyprotectapiv2.UnmarshalImportToken(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyAllowedIPPolicyData successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyAllowedIPPolicyData)
			model.Enabled = core.BoolPtr(true)
			model.Attributes = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyAllowedIPPolicyData
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyAllowedIPPolicyData(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyAllowedIPPolicyDataAttributes successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyAllowedIPPolicyDataAttributes)
			model.AllowedIp = []string{"10.1.0.0/32", "10.0.0.0/24", "192.0.2.0/32", "198.51.100.0/24", "2001:db8::/60"}

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyAllowedIPPolicyDataAttributes
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyAllowedIPPolicyDataAttributes(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyAllowedNetworkPolicyData successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData)
			model.Enabled = core.BoolPtr(true)
			model.Attributes = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyData
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyAllowedNetworkPolicyData(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyAllowedNetworkPolicyDataAttributes successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyDataAttributes)
			model.AllowedNetwork = core.StringPtr("public-and-private")

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyAllowedNetworkPolicyDataAttributes
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyAllowedNetworkPolicyDataAttributes(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyKeyCreateImportAccessPolicyData successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyKeyCreateImportAccessPolicyData)
			model.Enabled = core.BoolPtr(true)
			model.Attributes = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyKeyCreateImportAccessPolicyData
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyKeyCreateImportAccessPolicyData(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyKeyCreateImportAccessPolicyDataAttributes successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyKeyCreateImportAccessPolicyDataAttributes)
			model.CreateRootKey = core.BoolPtr(true)
			model.CreateStandardKey = core.BoolPtr(true)
			model.ImportRootKey = core.BoolPtr(true)
			model.ImportStandardKey = core.BoolPtr(true)
			model.EnforceToken = core.BoolPtr(true)

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyKeyCreateImportAccessPolicyDataAttributes
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyKeyCreateImportAccessPolicyDataAttributes(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyRotationPolicyData successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyRotationPolicyData)
			model.Enabled = core.BoolPtr(true)
			model.Attributes = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyRotationPolicyData
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyRotationPolicyData(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalInstancePolicyRotationPolicyDataAttributes successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.InstancePolicyRotationPolicyDataAttributes)
			model.IntervalMonth = core.Int64Ptr(int64(3))

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.InstancePolicyRotationPolicyDataAttributes
			err = ibmkeyprotectapiv2.UnmarshalInstancePolicyRotationPolicyDataAttributes(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalKMIPProfileDataBody successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.KMIPProfileDataBody)
			model.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.KMIPProfileDataBody
			err = ibmkeyprotectapiv2.UnmarshalKMIPProfileDataBody(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalKeyPolicyDualAuthDelete successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDelete)
			model.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
			model.DualAuthDelete = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.KeyPolicyDualAuthDelete
			err = ibmkeyprotectapiv2.UnmarshalKeyPolicyDualAuthDelete(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalKeyPolicyDualAuthDeleteDualAuthDelete successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete)
			model.Enabled = core.BoolPtr(true)

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.KeyPolicyDualAuthDeleteDualAuthDelete
			err = ibmkeyprotectapiv2.UnmarshalKeyPolicyDualAuthDeleteDualAuthDelete(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalKeyPolicyRotation successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.KeyPolicyRotation)
			model.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
			model.Rotation = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.KeyPolicyRotation
			err = ibmkeyprotectapiv2.UnmarshalKeyPolicyRotation(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalKeyPolicyRotationRotation successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.KeyPolicyRotationRotation)
			model.Enabled = core.BoolPtr(true)
			model.IntervalMonth = core.Int64Ptr(int64(1))

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.KeyPolicyRotationRotation
			err = ibmkeyprotectapiv2.UnmarshalKeyPolicyRotationRotation(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalMetricsProperties successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.MetricsProperties)
			model.Enabled = core.BoolPtr(true)

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.MetricsProperties
			err = ibmkeyprotectapiv2.UnmarshalMetricsProperties(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOf successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOf)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOf
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOf(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfResourcesItem)
			model.PolicyType = core.StringPtr("allowedNetwork")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem)
			model.PolicyType = core.StringPtr("allowedIP")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem)
			model.PolicyType = core.StringPtr("allowedNetwork")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem)
			model.PolicyType = core.StringPtr("keyCreateImportAccess")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem)
			model.PolicyType = core.StringPtr("metrics")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem)
			model.PolicyType = core.StringPtr("rotation")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePolicyDualAuthDeleteResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePolicyDualAuthDeleteResourcesItem)
			model.PolicyType = core.StringPtr("dualAuthDelete")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePolicyDualAuthDeleteResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePolicyDualAuthDeleteResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetKeyPoliciesOneOf successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOf)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetKeyPoliciesOneOf
			err = ibmkeyprotectapiv2.UnmarshalSetKeyPoliciesOneOf(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetMultipleInstancePoliciesResourcesItem successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItem)
			model.PolicyType = core.StringPtr("allowedNetwork")
			model.PolicyData = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItem
			err = ibmkeyprotectapiv2.UnmarshalSetMultipleInstancePoliciesResourcesItem(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetMultipleInstancePoliciesResourcesItemPolicyData successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItemPolicyData)
			model.Enabled = core.BoolPtr(true)
			model.Attributes = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItemPolicyData
			err = ibmkeyprotectapiv2.UnmarshalSetMultipleInstancePoliciesResourcesItemPolicyData(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetMultipleInstancePoliciesResourcesItemPolicyDataAttributes successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes)
			model.AllowedNetwork = core.StringPtr("public-and-private")
			model.AllowedIp = []string{"10.1.0.0/32", "10.0.0.0/24", "192.0.2.0/32", "198.51.100.0/24", "2001:db8::/60"}
			model.CreateRootKey = core.BoolPtr(true)
			model.CreateStandardKey = core.BoolPtr(true)
			model.ImportRootKey = core.BoolPtr(true)
			model.ImportStandardKey = core.BoolPtr(true)
			model.EnforceToken = core.BoolPtr(true)
			model.IntervalMonth = core.Int64Ptr(int64(3))

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes
			err = ibmkeyprotectapiv2.UnmarshalSetMultipleInstancePoliciesResourcesItemPolicyDataAttributes(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetMultipleKeyPoliciesResource successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetMultipleKeyPoliciesResource)
			model.Type = core.StringPtr("application/vnd.ibm.kms.policy+json")
			model.DualAuthDelete = nil
			model.Rotation = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetMultipleKeyPoliciesResource
			err = ibmkeyprotectapiv2.UnmarshalSetMultipleKeyPoliciesResource(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalKMIPProfileDataBodyKMIPProfileDataNative successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative)
			model.CrkID = core.StringPtr("feddecaf-0000-0000-0000-1234567890ab")

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.KMIPProfileDataBodyKMIPProfileDataNative
			err = ibmkeyprotectapiv2.UnmarshalKMIPProfileDataBodyKMIPProfileDataNative(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedIP successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedIP)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedIP
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedIP(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyMetrics successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyMetrics)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyMetrics
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyMetrics(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetInstancePolicyRotation successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyRotation)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetInstancePolicyRotation
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetInstancePolicyRotation(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetInstancePoliciesOneOfSetMultipleInstancePolicies successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetMultipleInstancePolicies)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetInstancePoliciesOneOfSetMultipleInstancePolicies
			err = ibmkeyprotectapiv2.UnmarshalSetInstancePoliciesOneOfSetMultipleInstancePolicies(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete
			err = ibmkeyprotectapiv2.UnmarshalSetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetKeyPoliciesOneOfSetKeyPolicyRotation successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyRotation)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetKeyPolicyRotation
			err = ibmkeyprotectapiv2.UnmarshalSetKeyPoliciesOneOfSetKeyPolicyRotation(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
		It(`Invoke UnmarshalSetKeyPoliciesOneOfSetMultipleKeyPolicies successfully`, func() {
			// Construct an instance of the model.
			model := new(ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetMultipleKeyPolicies)
			model.Metadata = nil
			model.Resources = nil

			b, err := json.Marshal(model)
			Expect(err).To(BeNil())

			var raw map[string]json.RawMessage
			err = json.Unmarshal(b, &raw)
			Expect(err).To(BeNil())

			var result *ibmkeyprotectapiv2.SetKeyPoliciesOneOfSetMultipleKeyPolicies
			err = ibmkeyprotectapiv2.UnmarshalSetKeyPoliciesOneOfSetMultipleKeyPolicies(raw, &result)
			Expect(err).To(BeNil())
			Expect(result).ToNot(BeNil())
			Expect(result).To(Equal(model))
		})
	})
	Describe(`Utility function tests`, func() {
		It(`Invoke CreateMockByteArray() successfully`, func() {
			mockByteArray := CreateMockByteArray("VGhpcyBpcyBhIHRlc3Qgb2YgdGhlIGVtZXJnZW5jeSBicm9hZGNhc3Qgc3lzdGVt")
			Expect(mockByteArray).ToNot(BeNil())
		})
		It(`Invoke CreateMockUUID() successfully`, func() {
			mockUUID := CreateMockUUID("9fab83da-98cb-4f18-a7ba-b6f0435c9673")
			Expect(mockUUID).ToNot(BeNil())
		})
		It(`Invoke CreateMockReader() successfully`, func() {
			mockReader := CreateMockReader("This is a test.")
			Expect(mockReader).ToNot(BeNil())
		})
		It(`Invoke CreateMockDate() successfully`, func() {
			mockDate := CreateMockDate("2019-01-01")
			Expect(mockDate).ToNot(BeNil())
		})
		It(`Invoke CreateMockDateTime() successfully`, func() {
			mockDateTime := CreateMockDateTime("2019-01-01T12:00:00.000Z")
			Expect(mockDateTime).ToNot(BeNil())
		})
	})
})

//
// Utility functions used by the generated test code
//

func CreateMockByteArray(encodedString string) *[]byte {
	ba, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		panic(err)
	}
	return &ba
}

func CreateMockUUID(mockData string) *strfmt.UUID {
	uuid := strfmt.UUID(mockData)
	return &uuid
}

func CreateMockReader(mockData string) io.ReadCloser {
	return io.NopCloser(bytes.NewReader([]byte(mockData)))
}

func CreateMockDate(mockData string) *strfmt.Date {
	d, err := core.ParseDate(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func CreateMockDateTime(mockData string) *strfmt.DateTime {
	d, err := core.ParseDateTime(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func SetTestEnvironment(testEnvironment map[string]string) {
	for key, value := range testEnvironment {
		os.Setenv(key, value)
	}
}

func ClearTestEnvironment(testEnvironment map[string]string) {
	for key := range testEnvironment {
		os.Unsetenv(key)
	}
}
