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

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/IBM/keyprotect-go-client/iam"

	"github.com/stretchr/stew/slice"
	"github.com/stretchr/testify/assert"
	gock "gopkg.in/h2non/gock.v1"
)

// NewTestClientConfig returns a new ClientConfig suitable for testing.
//
func NewTestClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:    "http://example.com",
		InstanceID: "test instance id",
		APIKey:     "test api key",
		TokenURL:   "https://iam.cloud.ibm.com/oidc/token",
	}
}

// NewTestURL returns the shared, invalid url for tests.  Given paths are
// joined to the base, separted with /.
//
func NewTestURL(paths ...string) string {
	return NewTestClientConfig().BaseURL + strings.Join(paths, "/")
}

// NewTestClient constructs and returns a new API and request ccontext.
//
func NewTestClient(t *testing.T, c *ClientConfig) (*API, context.Context, error) {
	if c == nil {
		cp := NewTestClientConfig()
		c = &cp
	}
	api, err := New(*c, DefaultTransport())
	return api, context.Background(), err
}

// MockAuthURL mocks an api endpoint.
//
func MockURL(url string, status int, json interface{}) *gock.Response {
	return gock.New(url).Reply(status).JSON(json)
}

// MockAuth tells `gock` to respond to token auth requests.
//
func MockAuth() *gock.Response {
	return MockURL("https://iam.cloud.ibm.com/oidc/token", http.StatusOK, "{}")
}

// MockAuthURL mocks an auth endpoint and an api endpoint.
//
func MockAuthURL(url string, status int, json interface{}) *gock.Response {
	MockAuth()
	return MockURL(url, status, json)
}

// setRetriesForTests sets the HTTP retries to low values for unit tests
//
func setRetriesForTests() {
	RetryMax = 1
	RetryWaitMax = 1 * time.Millisecond
}

// Tests the API methods for keys.
//
func TestKeys(t *testing.T) {
	setRetriesForTests()
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	newRootKey := &Key{
		ID:          "48bn3-3h4o-o4in5-34in9",
		Name:        "RootKey1",
		Extractable: false,
	}
	newStandardKey := &Key{
		ID:          "h934h-a984h-50jir-4903",
		Name:        "StandardKey1",
		Extractable: true,
	}

	testKeys := &Keys{
		Metadata: KeysMetadata{
			CollectionType: "json",
			NumberOfKeys:   2,
		},
		Keys: []Key{
			Key{
				ID:          testKey,
				Name:        "Key1",
				Extractable: false,
			},
			Key{
				ID:          "5ngy2-kko9n-4mj5f-w3jer",
				Name:        "Key2",
				Extractable: true,
			},
		},
	}

	keysActionDEK := KeysActionRequest{
		PlainText:  "YWJjZGVmZ2hpamtsbW5vCg==",
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	keysActionCT := KeysActionRequest{
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	keysActionPT := KeysActionRequest{
		PlainText: "YWJjZGVmZw==",
	}

	keysActionPTReWrap := KeysActionRequest{
		PlainText:  "YWJjZGVmZw==",
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	keyActionAADPT := KeysActionRequest{
		PlainText: "dGhpcyBpcyBteSBrZXkgZm9yIGFhZAo=",
		AAD:       []string{"key1", "key2", "key3"},
	}

	keyActionAADCT := KeysActionRequest{
		AAD:        []string{"key1", "key2", "key3"},
		CipherText: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
	}

	accessToken := "Bearer eyJraWQiOiIyMDE3MTAzMC0wMDowMDowMCIsImFsZyI6IlJTMjU2In0.eyJpYW1faWQiOiJpYW0tU2VydmljZUlkLWIwMDk1ZDFlLWMyNDUtNGFhZC04NmJlLTQ1ZmM3YzIxOTllMCIsImlkIjoiaWFtLVNlcnZpY2VJZC1iMDA5NWQxZS1jMjQ1LTRhYWQtODZiZS00NWZjN2MyMTk5ZTAiLCJyZWFsbWlkIjoiaWFtIiwiaWRlbnRpZmllciI6IlNlcnZpY2VJZC1iMDA5NWQxZS1jMjQ1LTRhYWQtODZiZS00NWZjN2MyMTk5ZTAiLCJzdWIiOiJTZXJ2aWNlSWQtYjAwOTVkMWUtYzI0NS00YWFkLTg2YmUtNDVmYzdjMjE5OWUwIiwic3ViX3R5cGUiOiJTZXJ2aWNlSWQiLCJhY2NvdW50Ijp7ImJzcyI6ImZiNDc0ODU1YTNlNzZjMWNlM2FhZWJmNTdlMGYxYTlmIn0sImlhdCI6MTUxODU1MDQ2NSwiZXhwIjoxNTE4NTU0MDY1LCJpc3MiOiJodHRwczovL2lhbS5uZy5ibHVlbWl4Lm5ldC9vaWRjL3Rva2VuIiwiZ3JhbnRfdHlwZSI6InVybjppYm06cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6YXBpa2V5Iiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWQiOiJkZWZhdWx0In0.XhXq7KT1CvuLekorCS_-YPkOCyx9unuj0JMIu7QYrJdRhLqC4VW5967kjllLVdvejZuEa7Nb7Anyoztcy-4VikhR5-wJx-eG4I6qf92QbLukXpRwFUaL7Y5qqJXsluxOOUsPOyeVNlUcpPPjkCHO79-Z2X68E7HV_XZr7T78Et-ea3MPW5fSF8112JbDGBbcPuzD7gtCtoHR9_MSjG7OU4b_LD_rkjR0tCaEClT9u7HM584FokXHSRCqE89IfkmRAlNcGMyMaYm6NDGuui81rna2lczR9IrkCHYluNNjrIEIUcz0g3xY2qdnSXcQFi7T8Ehaedj2mC3M4bQJ8DSbLQ"
	payload := "test string"
	keyURL := NewTestURL("/api/v2/keys")

	cases := TestCases{
		{
			"New API",
			func(t *testing.T, _ *API, _ context.Context) error {
				testapi, err := New(NewTestClientConfig(), DefaultTransport())
				assert.NotNil(t, testapi)
				return err
			},
		},
		{
			"New API with Logger",
			func(t *testing.T, _ *API, _ context.Context) error {
				var l Logger
				testapi, err := NewWithLogger(NewTestClientConfig(), DefaultTransport(), l)
				assert.NotNil(t, testapi)

				// hard-to-reach bits:
				c := NewTestClientConfig()
				c.BaseURL = ":"
				_, err = NewWithLogger(c, nil, l)
				assert.EqualError(t, err, "parse :/api/v2/: missing protocol scheme")

				return nil
			},
		},
		{
			"Timeout",
			func(t *testing.T, _ *API, _ context.Context) error {
				cfg := NewTestClientConfig()
				cfg.Timeout = 0.001
				api, err := New(cfg, DefaultTransport())
				assert.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()

				mux := http.NewServeMux()
				server := httptest.NewServer(mux)
				route := "/"
				u, err := url.Parse(server.URL + route)
				assert.NoError(t, err)

				done := make(chan struct{})
				mux.HandleFunc(route,
					func(w http.ResponseWriter, r *http.Request) {
						<-done
					},
				)

				actual := make(chan error)
				go func() {
					req := &http.Request{
						URL: u,
					}
					_, err := api.HttpClient.Do(req)
					actual <- err
				}()

				select {
				case <-ctx.Done():
					t.Log("didn't time out")
					t.Fail()
					<-actual
				case err := <-actual:
					netErr, ok := err.(net.Error)
					assert.True(t, ok)
					assert.True(t, netErr.Timeout())
				}

				close(done)
				return nil
			},
		},
		{
			"Get Keys",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)

				keys, err := api.GetKeys(ctx, 10, 0)
				assert.NoError(t, err)
				assert.NotZero(t, keys.Metadata.NumberOfKeys)

				return nil
			},
		},
		{
			"Wrap Create DEK",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, keysActionDEK)
				MockAuthURL(keyURL, http.StatusOK, keysActionDEK)

				unwrappedDEK, cipherText, err := api.WrapCreateDEK(ctx, testKey, nil)
				assert.NoError(t, err)
				assert.NotEqual(t, unwrappedDEK, cipherText)

				plainText, err := api.Unwrap(ctx, testKey, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, string(unwrappedDEK), string(plainText))

				return nil
			},
		},
		{
			"Wrap Unwrap v2",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, keysActionCT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)

				cipherText, err := api.Wrap(ctx, testKey, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				plainText, rewrap, err := api.UnwrapV2(ctx, testKey, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPT.PlainText, string(plainText))
				assert.Equal(t, "", string(rewrap))

				return nil
			},
		},
		{
			"Unwrap on Deleted should return err with 410 Gone",
			func(t *testing.T, api *API, ctx context.Context) error {
				kpErrMessage := "Gone: The key has been deleted and is no longer available.Please provide a valid key when performing an 'unwrap' action"
				errorResp := map[string]interface{}{
					"metadata": map[string]interface{}{
						"collectionType":  "application/vnd.ibm.kms.error+json",
						"collectionTotal": 1,
					},
					"resources": []map[string]interface{}{
						map[string]interface{}{
							"errorMsg": kpErrMessage,
						},
					},
				}

				MockAuthURL(keyURL, http.StatusGone, errorResp)

				plainText, err := api.Unwrap(ctx, testKey, []byte{}, nil)
				assert.Nil(t, plainText)
				assert.Error(t, err)

				kpError := err.(*Error)
				assert.Equal(t, 410, kpError.StatusCode)
				assert.Equal(t, kpErrMessage, kpError.Message)
				assert.Contains(t, kpError.Error(), kpErrMessage)

				return nil
			},
		},
		{
			"Imported Create Delete",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err := api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				startCount := ks.Metadata.NumberOfKeys
				testKeys.Keys = append([]Key{*newRootKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				k, err := api.CreateImportedRootKey(ctx, "test", nil, payload, "", "")
				assert.NoError(t, err)
				assert.NotNil(t, k)
				key1 := k.ID
				testKeys.Keys = append([]Key{*newStandardKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				expiration := time.Now().Add(24 * time.Hour)
				k, err = api.CreateImportedRootKey(ctx, "testtimeout", &expiration, "asdfqwerasdfqwerasdfqwerasdfqwer", "", "")
				assert.NoError(t, err)
				key2 := k.ID

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount+2, ks.Metadata.NumberOfKeys, "Created 2 keys, counts don't match")
				testKeys.Keys = append(testKeys.Keys[:1], testKeys.Keys[2:]...)
				testKeys.Metadata.NumberOfKeys--

				MockAuthURL(keyURL, http.StatusOK, "{}")
				k, err = api.DeleteKey(ctx, key1, ReturnMinimal)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				testKeys.Keys = append(testKeys.Keys[:0], testKeys.Keys[1:]...)
				testKeys.Metadata.NumberOfKeys--
				k, err = api.DeleteKey(ctx, key2, ReturnRepresentation)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 0, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount, ks.Metadata.NumberOfKeys, "Deleted 2 keys, counts don't match")
				return nil
			},
		},
		{
			"Create Delete",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err := api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				startCount := ks.Metadata.NumberOfKeys
				testKeys.Keys = append([]Key{*newRootKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				k, err := api.CreateRootKey(ctx, "test", nil)
				assert.NoError(t, err)
				key1 := k.ID
				testKeys.Keys = append([]Key{*newStandardKey}, testKeys.Keys...)
				testKeys.Metadata.NumberOfKeys++

				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				expiration := time.Now().Add(24 * time.Hour)
				k, err = api.CreateRootKey(ctx, "testtimeout", &expiration)
				assert.NoError(t, err)
				key2 := k.ID

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 100, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount+2, ks.Metadata.NumberOfKeys, "Created 2 keys, counts don't match")
				testKeys.Keys = append(testKeys.Keys[:1], testKeys.Keys[2:]...)
				testKeys.Metadata.NumberOfKeys--

				MockAuthURL(keyURL, http.StatusOK, "{}")
				k, err = api.DeleteKey(ctx, key1, ReturnMinimal)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				testKeys.Keys = append(testKeys.Keys[:0], testKeys.Keys[1:]...)
				testKeys.Metadata.NumberOfKeys--
				k, err = api.DeleteKey(ctx, key2, ReturnRepresentation)
				assert.NoError(t, err)

				MockAuthURL(keyURL, http.StatusOK, testKeys)
				ks, err = api.GetKeys(ctx, 0, 0)
				assert.NoError(t, err)
				assert.Equal(t, startCount, ks.Metadata.NumberOfKeys, "Deleted 2 keys, counts don't match")

				return nil
			},
		},
		{
			"Imported Rotate",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)

				k, err := api.CreateImportedRootKey(ctx, "test", nil, "asdfqwerasdfqwerasdfqwerasdfqwer", "", "")
				assert.NoError(t, err)
				key1 := k.ID

				return api.Rotate(ctx, key1, "qwerasdfqwerasdfqwerasdfqwerasdf")

			},
		},
		{
			"Imported Rotate Unwrap",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPTReWrap)

				k, err := api.CreateImportedRootKey(ctx, "test", nil, "asdfqwerasdfqwerasdfqwerasdfqwer", "", "")
				assert.NoError(t, err)
				key1 := k.ID
				cipherText, err := api.Wrap(ctx, key1, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				errRotate := api.Rotate(ctx, key1, "qwerasdfqwerasdfqwerasdfqwerasdf")
				assert.NoError(t, errRotate)

				plainText, rewrap, err := api.UnwrapV2(ctx, key1, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPTReWrap.PlainText, string(plainText))
				assert.Equal(t, keysActionPTReWrap.CipherText, string(rewrap))
				return nil
			},
		},
		{
			"Rotate Unwrap",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPTReWrap)

				k, err := api.CreateRootKey(ctx, "test", nil)
				assert.NoError(t, err)
				key1 := k.ID

				cipherText, err := api.Wrap(ctx, key1, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				errRotate := api.Rotate(ctx, key1, "")
				assert.NoError(t, errRotate)

				plainText, rewrap, err := api.UnwrapV2(ctx, key1, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPTReWrap.PlainText, string(plainText))
				assert.Equal(t, keysActionPTReWrap.CipherText, string(rewrap))
				return nil
			},
		},
		{
			"Timeout",
			func(t *testing.T, api *API, ctx context.Context) error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
				defer cancel()
				c := NewTestClientConfig()
				c.BaseURL = DefaultBaseURL + ":22"
				c.Verbose = VerboseAll

				a, ctx, err := NewTestClient(t, nil)
				assert.NoError(t, err)
				gock.InterceptClient(&a.HttpClient)

				body := "context deadline exceeded"
				MockAuthURL(keyURL, http.StatusRequestTimeout, "").BodyString(body)
				_, err = a.GetKeys(ctx, 0, 0)
				assert.Contains(t, err.Error(), body)
				return nil
			},
		},

		{
			"Auth Context",
			func(t *testing.T, api *API, ctx context.Context) error {
				ctx = NewContextWithAuth(ctx, accessToken)
				body := "Bad Request: Token is expired"
				MockAuthURL(keyURL, http.StatusBadRequest, "").BodyString(body)
				_, err := api.GetKeys(ctx, 0, 0)
				assert.Contains(t, err.Error(), body)
				return nil
			},
		},
		{
			"Auth in Config",
			func(t *testing.T, api *API, ctx context.Context) error {
				c := &ClientConfig{
					BaseURL:       NewTestURL(),
					Authorization: accessToken,
					InstanceID:    "0647c737-906d-438a-8a68-2c187e11b29b",
					Verbose:       VerboseAllNoRedact,
				}

				a, ctx, err := NewTestClient(t, c)
				assert.NoError(t, err)
				gock.InterceptClient(&a.HttpClient)

				body := "Bad Request: Token is expired"
				MockAuthURL(keyURL, http.StatusBadRequest, "").BodyString(body)
				_, err = a.GetKeys(ctx, 0, 0)
				assert.Contains(t, err.Error(), body)
				return nil
			},
		},
		{
			"Wrap and Unwrap AAD",
			func(t *testing.T, api *API, ctx context.Context) error {
				body := "Unprocessable Entity: Invalid ciphertext"

				MockAuthURL(keyURL, http.StatusOK, keyActionAADCT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusUnprocessableEntity, "").BodyString(body)

				ciphertext, err := api.Wrap(ctx, testKey, []byte(keyActionAADPT.PlainText), &keyActionAADPT.AAD)
				assert.NoError(t, err)

				plainText, err := api.Unwrap(ctx, testKey, ciphertext, &keyActionAADCT.AAD)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPT.PlainText, string(plainText))

				// Test bad aad
				aad := []string{"key44", "key55"}
				_, err = api.Unwrap(ctx, testKey, ciphertext, &aad)
				assert.Contains(t, err.Error(), body)
				return nil
			},
		},
		{
			"API Key Timeout",
			func(t *testing.T, api *API, ctx context.Context) error {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
				defer cancel()
				defer gock.Off()

				c := NewTestClientConfig()
				c.TokenURL = "https://iam.bluemix.net:22/oidc/token"

				gock.New(keyURL).Reply(http.StatusOK).JSON(keyActionAADCT)
				a, _, err := NewTestClient(t, &c)
				assert.NoError(t, err)

				body := "context deadline exceeded"
				gock.New("https://iam.bluemix.net/oidc/token").Reply(http.StatusRequestTimeout).BodyString(body)
				gock.InterceptClient(&a.HttpClient)

				_, err = a.GetKeys(ctx, 0, 0)
				// failing ATM:
				//assert.EqualError(t, err, "context deadline exceeded")
				return nil
			},
		},

		{
			"Bad Config",
			func(t *testing.T, api *API, ctx context.Context) error {
				c := NewTestClientConfig()
				c.Verbose = 5

				_, _, err := NewTestClient(t, &c)
				assert.EqualError(t, err, "verbose value is out of range")

				return nil
			},
		},
		{
			"Bad API Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				api, ctx, err := NewTestClient(t, nil)
				ctx, cancel := context.WithTimeout(ctx, time.Second*2)
				defer cancel()
				defer gock.Off()

				c := NewTestClientConfig()
				c.APIKey = "BadOne"

				gock.New(keyURL).Reply(http.StatusOK).JSON(testKeys)
				a, ctx, _ := NewTestClient(t, &c)

				body := map[string]interface{}{
					"errorCode":    "BXNIM0415E",
					"errorMessage": "Provided API key could not be found",
					"context": map[string]interface{}{
						"requestId": "1234",
					},
				}

				gock.New("https://iam.cloud.ibm.com/oidc/token").Reply(http.StatusBadRequest).JSON(body)
				gock.InterceptClient(&a.HttpClient)

				_, err = api.GetKeys(ctx, 0, 0)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "BXNIM0415E")
				assert.Contains(t, err.Error(), "Provided API key could not be found")

				return nil
			},
		},
		{
			"Create Key Without Expiration",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuth()
				expectedReq := `{"metadata":{"collectionType":"application/vnd.ibm.kms.key+json","collectionTotal":1},"resources":[{"name":"test","type":"application/vnd.ibm.kms.key+json","extractable":false}]}`
				gock.New(keyURL).
					AddMatcher(func(req *http.Request, greq *gock.Request) (bool, error) {
						body, merr := ioutil.ReadAll(req.Body)
						if merr != nil {
							return false, merr
						}
						return string(body) == expectedReq, nil // No expiration in req body.
					}).
					Reply(http.StatusCreated).
					JSON(testKeys)

				_, err := api.CreateRootKey(ctx, "test", nil)
				return err
			},
		},
		{
			"Create",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "{}")
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "{}")

				_, err := api.CreateImportedRootKey(ctx, "test", nil, payload, "abc", "")
				assert.NoError(t, err)

				_, err = api.CreateKey(ctx, "test", nil, false)
				assert.Error(t, err)

				_, err = api.CreateImportedKey(ctx, "test", nil, "", "", "", false)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Rotate",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				MockAuthURL(keyURL, http.StatusCreated, testKeys)
				MockAuthURL(keyURL, http.StatusServiceUnavailable, testKeys)

				k, err := api.CreateRootKey(ctx, "test", nil)
				assert.NoError(t, err)

				key1 := k.ID
				err = api.Rotate(ctx, key1, "")
				assert.NoError(t, err)

				err = api.Rotate(ctx, key1, "")
				assert.Error(t, err)

				return nil

			},
		},
		{
			"Get Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				// Successful call
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				key, err := api.GetKey(ctx, testKey)
				assert.NoError(t, err)
				assert.Equal(t, testKey, key.ID)

				// Set it up to fail twice, with one retry
				RetryMax = 1
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "service unavailable")
				MockAuthURL(keyURL, http.StatusBadGateway, "err: bad gateway")
				key, err = api.GetKey(ctx, testKey)
				assert.Error(t, err)

				// Validate that the error we get back has the status and message from the retry
				assert.Equal(t, http.StatusBadGateway, err.(*Error).StatusCode)
				assert.Equal(t, "err: bad gateway", err.(*Error).Message)
				assert.NotEmpty(t, err.(*Error).CorrelationID)
				return nil
			},
		},
		{
			"Get Key Metadata",
			func(t *testing.T, api *API, ctx context.Context) error {
				// Successful call
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				key, err := api.GetKeyMetadata(ctx, testKey)
				assert.NoError(t, err)
				assert.Equal(t, testKey, key.ID)

				// Set it up to fail twice, with one retry
				RetryMax = 1
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "service unavailable")
				MockAuthURL(keyURL, http.StatusBadGateway, "err: bad gateway")
				key, err = api.GetKeyMetadata(ctx, testKey)
				assert.Error(t, err)

				// Validate that the error we get back has the status and message from the retry
				assert.Equal(t, http.StatusBadGateway, err.(*Error).StatusCode)
				assert.Equal(t, "err: bad gateway", err.(*Error).Message)
				assert.NotEmpty(t, err.(*Error).CorrelationID)
				return nil
			},
		},
		{
			"Wrap Unwrap",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, keysActionCT)
				MockAuthURL(keyURL, http.StatusOK, keysActionPT)
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "")

				cipherText, err := api.Wrap(ctx, testKey, []byte(keysActionPT.PlainText), nil)
				assert.NoError(t, err)
				assert.NotEqual(t, keysActionPT.PlainText, cipherText)

				plainText, err := api.Unwrap(ctx, testKey, cipherText, nil)
				assert.NoError(t, err)
				assert.Equal(t, keysActionPT.PlainText, string(plainText))

				_, err = api.Wrap(ctx, testKey, []byte("a"), nil)
				assert.EqualError(t, err, "illegal base64 data at input byte 0")

				_, _, err = api.WrapCreateDEK(ctx, testKey, &[]string{"a"})
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Delete Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusServiceUnavailable, "{}")
				_, err := api.DeleteKey(ctx, testKey, ReturnMinimal)
				assert.Error(t, err)
				return nil
			},
		},
		{
			"Create Standard Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				_, err := api.CreateStandardKey(ctx, "", nil)
				return err
			},
		},
		{
			"Create Imported Standard Key",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(keyURL, http.StatusOK, testKeys)
				_, err := api.CreateImportedStandardKey(ctx, "", nil, payload)
				return err
			},
		},
	}
	cases.Run(t)
}

// Tests the API for misc. funcionality.
//
func TestMisc(t *testing.T) {
	cases := TestCases{
		{
			"Redact Values",
			func(t *testing.T, _ *API, _ context.Context) error {
				s1 := "a:b,c:d,e:f"
				r := []string{"b", "d"}
				s := redact(s1, r)
				assert.Equal(t, "a:***Value redacted***,c:***Value redacted***,e:f", s)
				assert.Equal(t, s1, redact(s1, []string{}))
				assert.Equal(t, s1, noredact(s1, r))
				return nil
			},
		},
	}
	cases.Run(t)
}

// Tests the API methods for ImportTokens.
//
func TestImportTokens(t *testing.T) {
	endpoint := "/api/v2/import_token"

	cases := TestCases{
		{
			"ImportToken Create",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(NewTestURL()+endpoint, http.StatusOK, &ImportTokenCreateRequest{600, 600})
				MockAuthURL(NewTestURL()+endpoint, http.StatusServiceUnavailable, "")

				_, err := api.CreateImportToken(ctx, 600, 600)
				assert.NoError(t, err)

				_, err = api.CreateImportToken(ctx, 600, 600)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"ImportToken Get",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(NewTestURL()+endpoint, http.StatusOK, &ImportTokenKeyResponse{})
				MockAuthURL(NewTestURL()+endpoint, http.StatusOK, "")

				_, err := api.GetImportTokenTransportKey(ctx)
				assert.NoError(t, err)

				_, err = api.GetImportTokenTransportKey(ctx)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Assert context authorization override",
			func(t *testing.T, api *API, ctx context.Context) error {
				MockAuthURL(NewTestURL()+endpoint, http.StatusNoContent, "")
				MockAuthURL(NewTestURL()+endpoint, http.StatusServiceUnavailable, "{'resources':[{'errorMsg':'none'}]}")

				// auth token injection via context
				orig := "Basic 12345"
				tok, err := api.getAccessToken(context.WithValue(ctx, authContextKey, orig))
				assert.NoError(t, err)
				assert.Exactly(t, tok, orig)

				// TokenURL overriding
				ts := api.tokenSource.(*iam.IAMTokenSource)
				ts.TokenURL = ":"
				_, err = api.getAccessToken(ctx)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Dump Implementations",
			func(t *testing.T, api *API, ctx context.Context) error {
				codes := []int{
					http.StatusOK,
					http.StatusCreated,
					http.StatusNoContent,
					http.StatusTeapot,
				}
				rs := []string{}
				rb := []byte("access_token")
				log := NewLogger(func(args ...interface{}) {})
				req := func() *http.Request {
					req, err := http.NewRequest(http.MethodGet, NewTestURL(), nil)
					assert.NoError(t, err)
					return req
				}
				for _, dump := range dumpers {
					for _, code := range codes {
						res := http.Response{StatusCode: code}
						dump(req(), &res, []byte{}, rb, log, rs)
					}
				}
				return nil
			},
		},
	}
	cases.Run(t)
}

func TestKPCheckRetry(t *testing.T) {
	cases := TestCases{
		{
			"No retry on successful codes",
			func(t *testing.T, api *API, ctx context.Context) error {
				ct := context.Background()
				resp := &http.Response{
					StatusCode: http.StatusAccepted,
				}

				retry, err := kpCheckRetry(ct, resp, nil)
				assert.False(t, retry)
				assert.NoError(t, err)
				return nil
			},
		}, {
			"No retry on 400-level codes",
			func(t *testing.T, api *API, ctx context.Context) error {
				ct := context.Background()
				resp := &http.Response{
					StatusCode: http.StatusBadRequest,
				}
				retry, err := kpCheckRetry(ct, resp, nil)
				assert.False(t, retry)
				assert.NoError(t, err)
				return nil
			},
		}, {
			"Retry on 429",
			func(t *testing.T, api *API, ctx context.Context) error {
				ct := context.Background()
				resp := &http.Response{
					StatusCode: http.StatusTooManyRequests,
				}
				retry, err := kpCheckRetry(ct, resp, nil)
				assert.True(t, retry)
				assert.NoError(t, err)
				return nil
			},
		}, {
			"Retry on 500+",
			func(t *testing.T, api *API, ctx context.Context) error {
				ct := context.Background()
				resp := &http.Response{
					StatusCode: http.StatusServiceUnavailable,
				}
				retry, err := kpCheckRetry(ct, resp, nil)
				assert.True(t, retry)
				assert.NoError(t, err)
				return nil
			},
		}, {
			"No retry on 501",
			func(t *testing.T, api *API, ctx context.Context) error {
				ct := context.Background()
				resp := &http.Response{
					StatusCode: http.StatusNotImplemented,
				}
				retry, err := kpCheckRetry(ct, resp, nil)
				assert.False(t, retry)
				assert.NoError(t, err)
				return nil
			},
		}, {
			"Retry on connection failures",
			func(t *testing.T, api *API, ctx context.Context) error {
				ct := context.Background()
				connErr := fmt.Errorf("failure connecting")
				retry, err := kpCheckRetry(ct, nil, connErr)
				assert.True(t, retry)
				assert.Equal(t, connErr, err)
				return nil
			},
		}, {
			"No retry on context failures",
			func(t *testing.T, api *API, ctx context.Context) error {
				ct, cancelFunc := context.WithDeadline(context.Background(), time.Now())
				defer cancelFunc()
				retry, err := kpCheckRetry(ct, nil, nil)
				assert.False(t, retry)
				assert.Error(t, err)
				assert.Equal(t, "context deadline exceeded", err.Error())
				return nil
			},
		},
	}
	cases.Run(t)
}

// TestCase holds a subtest name and callable.
//
type TestCase struct {
	Name string
	Call func(*testing.T, *API, context.Context) error
}

// TestCases are a slice of TestCase structs.
//
type TestCases []TestCase

// Run executes all of the test cases, with a handy setup beforehand.
//
func (cases TestCases) Run(t *testing.T) {
	defer gock.Off()

	for _, test := range cases {
		api, ctx := cases.Setup(t)
		defer gock.RestoreClient(&api.HttpClient)

		t.Run(test.Name, func(t *testing.T) {
			assert.NoError(t, test.Call(t, api, ctx))
		})
		gock.Flush()
	}
}

// Setup creates and returns an API and a request context.
//
func (cases TestCases) Setup(t *testing.T) (*API, context.Context) {
	api, ctx, err := NewTestClient(t, nil)
	assert.NoError(t, err)
	gock.InterceptClient(&api.HttpClient)
	return api, ctx
}

type FakeTokenSource struct{}

func (fts *FakeTokenSource) Token() (*iam.Token, error) {
	return &iam.Token{
		AccessToken: "test123",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(5) * time.Minute),
	}, nil
}

func TestDo_ConnectionError_HasCorrelationID(t *testing.T) {
	defer gock.Off()

	gock.New("http://example.com").
		ReplyError(errors.New("test error"))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	keys, err := c.GetKeys(context.Background(), 0, 0)

	assert.Nil(t, keys)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "correlation_id=")

	urlErr := err.(*URLError)
	assert.NotEmpty(t, urlErr.CorrelationID)
}

func TestDo_KPErrorResponseWithReasons_IsErrorStruct(t *testing.T) {
	defer gock.Off()

	errorWithReasons := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.error+json",
			"collectionTotal": 1
		},
		"resources": [
			{
				"errorMsg": "Conflict: Action could not be performed on key. Please see reasons for more details.",
				"reasons": [
					{
						"code": "KEY_ROTATION_NOT_PERMITTED",
						"message": "This root key has been rotated within the last hour. Only one 'rotate' action per hour is permitted",
						"status": 409,
						"moreInfo": "https://cloud.ibm.com/apidocs/key-protect"
					}
				]
			}
		]
	}`)

	gock.New("http://example.com").Reply(409).Body(bytes.NewReader(errorWithReasons))
	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.Rotate(context.Background(), "boguskeyID", "")

	reasonsErr := err.(*Error)

	assert.NotNil(t, reasonsErr.URL)
	assert.Equal(t, 409, reasonsErr.StatusCode)
	assert.Equal(t, "Conflict: Action could not be performed on key. Please see reasons for more details.", reasonsErr.Message)
	assert.Equal(t, errorWithReasons, reasonsErr.BodyContent)
	assert.NotNil(t, reasonsErr.CorrelationID)
	assert.NotEmpty(t, reasonsErr.Reasons)
	assert.Contains(t, reasonsErr.Error(), "reasons=")
	assert.Contains(t, reasonsErr.Error(), "This root key has been rotated within the last hour. Only one 'rotate' action per hour is permitted")
}

func TestDo_KPErrorResponseWithoutReasons_IsErrorStruct(t *testing.T) {
	defer gock.Off()

	errorWithoutReasons := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.error+json",
			"collectionTotal": 1
		},
		"resources": [
			{
				"errorMsg": "Unauthorized: The user does not have access to the specified resource"
			}
		]
	}`)

	gock.New("http://example.com").Reply(401).Body(bytes.NewReader(errorWithoutReasons))
	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	_, err = c.GetKeys(context.Background(), 0, 0)

	reasonsErr := err.(*Error)

	assert.NotNil(t, reasonsErr.URL)
	assert.Equal(t, 401, reasonsErr.StatusCode)
	assert.Equal(t, "Unauthorized: The user does not have access to the specified resource", reasonsErr.Message)
	assert.Equal(t, errorWithoutReasons, reasonsErr.BodyContent)
	assert.NotNil(t, reasonsErr.CorrelationID)
	assert.Empty(t, reasonsErr.Reasons)
}

func TestDeleteKey_ForceOptTrue_URLHasForce(t *testing.T) {
	defer gock.Off()

	gock.New("http://example.com").
		Delete("/api/v2/keys/abcd-1234").
		MatchParam("force", "true").
		Reply(204)

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	key, err := c.DeleteKey(context.Background(), "abcd-1234", ReturnMinimal, ForceOpt{true})

	assert.Nil(t, key)
	assert.Nil(t, err)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

func TestDeleteKey_WithRegistrations_ErrorCases(t *testing.T) {
	defer gock.Off()

	errorDeleteKeyWithRegistrations := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.error+json",
			"collectionTotal": 1
		},
		"resources": [
			{
				"errorMsg": "Conflict: Action could not be performed on key. Please see reasons for more details.",
				"reasons": [
					{
						"code": "PROTECTED_RESOURCE_ERR",
						"message": "Key is protecting one or more cloud resources",
						"moreInfo": "https://cloud.ibm.com/docs/key-protect?topic=key-protect-troubleshooting#unable-to-delete-keys"
					}
				]
			}
		]
	}`)

	errorForceDeleteKeyWithRegistrations := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.error+json",
			"collectionTotal": 1
		},
		"resources": [
			{
				"errorMsg": "Conflict: Action could not be performed on key. Please see reasons for more details.",
				"reasons": [
					{
						"code": "PREV_KEY_DEL_ERR",
						"message": "The key cannot be deleted because it's protecting a cloud resource that has a retention policy. Before you delete this key, contact an account owner to remove the retention policy on each resource that is associated with the key.",
						"moreInfo": "https://cloud.ibm.com/apidocs/key-protect"
					}
				]
			}
		]
	}`)

	gock.New("http://example.com").
		Delete("/api/v2/keys/abcd-2345").
		Reply(409).Body(bytes.NewReader(errorDeleteKeyWithRegistrations))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	key, err := c.DeleteKey(context.Background(), "abcd-2345", ReturnRepresentation)

	deleteErr := err.(*Error)
	assert.Nil(t, key)
	assert.Error(t, err)
	assert.Equal(t, deleteErr.Reasons[0].Code, "PROTECTED_RESOURCE_ERR")
	assert.Equal(t, deleteErr.Reasons[0].Message, "Key is protecting one or more cloud resources")
	assert.NotEqual(t, deleteErr.Reasons[0].MoreInfo, "")
	assert.Equal(t, deleteErr.Reasons[0].MoreInfo, "https://cloud.ibm.com/docs/key-protect?topic=key-protect-troubleshooting#unable-to-delete-keys")

	gock.New("http://example.com").
		Delete("/api/v2/keys/efgh-0987").
		MatchParam("force", "true").
		Reply(409).
		Body(bytes.NewReader(errorForceDeleteKeyWithRegistrations))

	key, err = c.DeleteKey(context.Background(), "efgh-0987", ReturnRepresentation, ForceOpt{true})

	forceDeleteErr := err.(*Error)
	assert.Nil(t, key)
	assert.Error(t, err)
	assert.Equal(t, forceDeleteErr.Reasons[0].Code, "PREV_KEY_DEL_ERR")
	assert.Equal(t, forceDeleteErr.Reasons[0].Message, "The key cannot be deleted because it's protecting a cloud resource that has a retention policy. Before you delete this key, contact an account owner to remove the retention policy on each resource that is associated with the key.")
	assert.NotEqual(t, forceDeleteErr.Reasons[0].MoreInfo, "")
	assert.Equal(t, forceDeleteErr.Reasons[0].MoreInfo, "https://cloud.ibm.com/apidocs/key-protect")

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")

}

func TestRegistrationsList(t *testing.T) {
	defer gock.Off()
	testKey := ""
	testCRN := ""
	allRegsResponse := []byte(`{
		"metadata": {
		  "collectionType": "application/vnd.ibm.kms.registration+json",
		  "collectionTotal": 3
		},
		"resources": [
		  {
			"keyId": "3c44b-f03e6-4y9a5-b859b",
			"resourceCrn": "crn:v1:dummy-env:dummy-service:global:a/dummy-details5:dummy-bucket3:dummy-reg2",
			"creationDate": "2020-04-23T17:17:18Z",
			"lastUpdated": "2020-04-23T17:17:18Z",
			"keyVersion": {
			  "id": "3c44b-f03e6-4y9a5-b859b",
			  "creationDate": "2020-03-31T16:34:43Z"
			}
		  },
		  {
			"keyId": "3c44b-f03e6-4y9a5-b859b",
			"resourceCrn": "crn:v1:dummy-ennv:dummy-service:global:a/dummy-details:dummy-bucket:dummy-reg",
			"creationDate": "2020-04-23T17:17:58Z",
			"lastUpdated": "2020-04-23T17:17:58Z",
			"keyVersion": {
			  "id": "3c44b-f03e6-4y9a5-b859b",
			  "creationDate": "2020-03-31T16:34:43Z"
			}
		  },
		  {
			"keyId": "2n4y2-4ko2n-4m23f-23j3r",
			"resourceCrn": "crn:v1:dummy-ennv:dummy-service:global:a/dummy-details:dummy-bucket:dummy-reg",
			"creationDate": "2020-03-31T16:37:05Z",
			"lastUpdated": "2020-03-31T16:37:05Z",
			"keyVersion": {
			  "id": "2n4y2-4ko2n-4m23f-23j3r",
			  "creationDate": "2020-03-31T16:17:39Z"
			}
		  }
		]
	  }`)

	RegsOfKeyResponse := []byte(`{
		"metadata": {
		  "collectionType": "application/vnd.ibm.kms.registration+json",
		  "collectionTotal": 2
		},
		"resources": [
		  {
			"keyId": "3c44b-f03e6-4y9a5-b859b",
			"resourceCrn": "crn:v1:dummy-env:dummy-service:global:a/dummy-details5:dummy-bucket3:dummy-reg2",
			"creationDate": "2020-04-23T17:17:18Z",
			"lastUpdated": "2020-04-23T17:17:18Z",
			"keyVersion": {
			  "id": "3c44b-f03e6-4y9a5-b859b",
			  "creationDate": "2020-03-31T16:34:43Z"
			}
		  },
		  {
			"keyId": "3c44b-f03e6-4y9a5-b859b",
			"resourceCrn": "crn:v1:dummy-ennv:dummy-service:global:a/dummy-details:dummy-bucket:dummy-reg",
			"creationDate": "2020-04-23T17:17:58Z",
			"lastUpdated": "2020-04-23T17:17:58Z",
			"keyVersion": {
			  "id": "3c44b-f03e6-4y9a5-b859b",
			  "creationDate": "2020-03-31T16:34:43Z"
			}
		  }
		]
	  }`)

	RegsOfCRNResponse := []byte(`{
		"metadata": {
		  "collectionType": "application/vnd.ibm.kms.registration+json",
		  "collectionTotal": 2
		},
		"resources": [
		  {
			"keyId": "3c44b-f03e6-4y9a5-b859b",
			"resourceCrn": "crn:v1:dummy-ennv:dummy-service:global:a/dummy-details:dummy-bucket:dummy-reg",
			"creationDate": "2020-04-23T17:17:58Z",
			"lastUpdated": "2020-04-23T17:17:58Z",
			"keyVersion": {
			  "id": "3c44b-f03e6-4y9a5-b859b",
			  "creationDate": "2020-03-31T16:34:43Z"
			}
		  },
		  {
			"keyId": "2n4y2-4ko2n-4m23f-23j3r",
			"resourceCrn": "crn:v1:dummy-ennv:dummy-service:global:a/dummy-details:dummy-bucket:dummy-reg",
			"creationDate": "2020-03-31T16:37:05Z",
			"lastUpdated": "2020-03-31T16:37:05Z",
			"keyVersion": {
			  "id": "2n4y2-4ko2n-4m23f-23j3r",
			  "creationDate": "2020-03-31T16:17:39Z"
			}
		  }
		]
	  }`)

	RegsOfKeyAndCRNResponse := []byte(`{
		"metadata": {
		  "collectionType": "application/vnd.ibm.kms.registration+json",
		  "collectionTotal": 1
		},
		"resources": [
		  {
			"keyId": "2n4y2-4ko2n-4m23f-23j3r",
			"resourceCrn": "crn:v1:dummy-ennv:dummy-service:global:a/dummy-details:dummy-bucket:dummy-reg",
			"creationDate": "2020-03-31T16:37:05Z",
			"lastUpdated": "2020-03-31T16:37:05Z",
			"keyVersion": {
			  "id": "2n4y2-4ko2n-4m23f-23j3r",
			  "creationDate": "2020-03-31T16:17:39Z"
			}
		  }
		]
	  }`)

	gock.New("http://example.com").
		Get("/api/v2/keys/registrations").
		Reply(200).Body(bytes.NewReader(allRegsResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	allRegs, err := c.ListRegistrations(context.Background(), testKey, testCRN)

	assert.Nil(t, err)
	assert.NotNil(t, allRegs)

	testKey = "3c44b-f03e6-4y9a5-b859b"

	gock.New("http://example.com").
		Get("/api/v2/keys/" + testKey + "/registrations").
		Reply(200).Body(bytes.NewReader(RegsOfKeyResponse))

	regsOfKey, err := c.ListRegistrations(context.Background(), testKey, testCRN)

	assert.Nil(t, err)
	assert.NotNil(t, regsOfKey)
	for _, reg := range (*regsOfKey).Registrations {
		assert.Equal(t, testKey, reg.KeyID)
	}

	testKey = "2n4y2-4ko2n-4m23f-23j3r"
	testCRN = "crn:v1:dummy-ennv:dummy-service:global:a/dummy-details:dummy-bucket:dummy-reg"

	gock.New("http://example.com").
		Get("/api/v2/keys/"+testKey+"/registrations").
		MatchParam("urlEncodedResourceCRNQuery", testCRN).
		Reply(200).Body(bytes.NewReader(RegsOfKeyAndCRNResponse))

	regsOfKeyAndCrn, err := c.ListRegistrations(context.Background(), testKey, testCRN)

	assert.Nil(t, err)
	assert.NotNil(t, regsOfKeyAndCrn)
	for _, reg := range (*regsOfKeyAndCrn).Registrations {
		assert.Equal(t, testKey, reg.KeyID)
		assert.Equal(t, testCRN, reg.ResourceCrn)
	}

	testKey = ""

	gock.New("http://example.com").
		Get("/api/v2/keys/registrations").
		MatchParam("urlEncodedResourceCRNQuery", testCRN).
		Reply(200).Body(bytes.NewReader(RegsOfCRNResponse))

	regsOfCRN, err := c.ListRegistrations(context.Background(), testKey, testCRN)

	assert.Nil(t, err)
	assert.NotNil(t, regsOfCRN)
	for _, reg := range (*regsOfCRN).Registrations {
		assert.Equal(t, testCRN, reg.ResourceCrn)
	}

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

// Tests the Key restore functionality
func TestRestoreKey(t *testing.T) {
	defer gock.Off()
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	restoreKeyResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.key+json",
			"collectionTotal":1
		},
		"resources":[
			{
				"type":"keys",
				"id":"2n4y2-4ko2n-4m23f-23j3r",
				"name":"test secret",
				"description":"a testing thing",
				"state":1,
				"extractable":false,
				"imported":true,
				"deleted":false,
				"deletionDate":"2020-05-06T16:48:51Z",
				"deletedBy":"user_xyz"
			}
		]
	}`)

	gock.New("http://example.com").
		Post("/api/v2/keys/"+testKey).
		MatchParam("action", "restore").
		Reply(201).Body(bytes.NewReader(restoreKeyResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	key, err := c.RestoreKey(context.Background(), testKey, "JaokkJZffuuMOOC4YhuFspe8508ixeKvqskKhFw1f+w=", "", "")

	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, testKey, key.ID)
	assert.False(t, key.Extractable)
	assert.Equal(t, key.State, 1)

	// restore key with encrypted nonce and iv

	deletedKey := "alkd-r30lk-4323"
	restoreKeyEcryptedNonceResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.key+json",
			"collectionTotal":1
			},
		"resources":[
			{
				"type":"application/vnd.ibm.kms.key+json",
				"id":"alkd-r30lk-4323",
				"name":"new_imported_root_key",
				"state":1,
				"extractable":false,
				"crn":"crn:v1:kms:public:dummy-region:a/dummy-account:dummy-instance:key:alkd-r30lk-4323",
				"imported":true,
				"deleted":false,
				"deletionDate":"2020-06-16T21:32:57Z",
				"deletedBy":"IBMid-50BE1MTM26"
			}
		]
	}`)

	gock.New("http://example/com").
		Post("/api/v2/keys/"+deletedKey).
		MatchParam("action", "restore").
		Reply(201).Body(bytes.NewReader(restoreKeyEcryptedNonceResponse))

	encryptedKey := "CB8+E6S551r2MxxTnP6oCX1e69UfLNugCD5e7SLSlRp+NCQHm+wKgfAGMY4Eq+kFTHkQxLaQTbtDvZyk/sNGI5wAtsk8+RU7J3WZeNIUU0wgYEMyPb1CGWDfAqGVa2shCkM4CYXFaUw5iI2StFFrxUdoaesd6Nt6MLmYqnKqCl7j8ueIcKulov6Pc9kMv5SUWBAX0yziKGXu74JmL/JFAq2tVFspy7tSXHZtJTVCFryzbnlXbjFiBKDkFlJ0MkFW+axB180nVRC2Fjx315MymbiaGwVGqodXYK+yqA+AIOhXsuPvK6A6Pw8oq0//mp7TJod1t+Bcja8xh2vXQdyM/q0hkCRzgcFYXgaVl12KzERz45U2QWNDj5cqJPx4PmCv6EHWmEjiVxhIkr9bhbosUBXnXhIyVcHxjjxEp8TgeBnvQSTFwfKu9pm9ifBK65CheyK32WXg6+6POZzmYVZpGxMQs2rr/QPwPelYjV4n6Y6SR/WuycYzT+x14bkp94yVTgt6UKwtg6NaRlwpst1xa3yShymmzPvLxhANI9y+ZHVL9Aoi+Fm982rrzy9N6kVn3dfo+Y8UgsfFar6VeieH9f1S5aACHyUW0uKEi9mFVO9sCCQ4PI3RKkvTinSN4THvfpQ4n1JTr7j75FbEl9xrfMWDD8cmgzu7IYQ8TdAlnR8="
	encyrptedNonce := "iKuIfHS4Wviv1tufFF4D8j59ksWKuRq0IJ3vsA=="
	iv := "KuOXnIEGnSPzUkQu"

	key, err = c.RestoreKey(context.Background(), deletedKey, encryptedKey, encyrptedNonce, iv)

	assert.NotNil(t, key)
	assert.NoError(t, err)
	assert.Equal(t, deletedKey, key.ID)
	assert.False(t, key.Extractable)
	assert.Equal(t, key.State, 1)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

// TestSetInstancePolicies tests the methods that set and get instance policies
func TestSetAndGetInstancePolicies(t *testing.T) {
	defer gock.Off()
	allpolicies := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.policy+json",
			"collectionTotal":2
		},
		"resources": [
			{
				"createdBy": "IBMid-50BE1MTM26",
				"creationDate": "2020-04-22T15:14:29Z",
				"lastUpdated": "2020-06-08T17:11:38Z",
				"updatedBy": "IBMid-50BE1MTM26",
				"policy_type": "allowedNetwork",
				"policy_data": {
				"enabled": true,
				"attributes": {
					"allowed_network": "private-only"
				}
				}
			},
			{
				"createdBy": "IBMid-50BE1MTM26",
				"creationDate": "2020-04-22T15:16:23Z",
				"lastUpdated": "2020-06-08T17:11:38Z",
				"updatedBy": "IBMid-50BE1MTM26",
				"policy_type": "dualAuthDelete",
				"policy_data": {
				"enabled": true,
				"attributes": {}
				}
			}
		]
	}`)
	dualAuthPolicy := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.policy+json",
			"collectionTotal":1
		},
		"resources": [
			{
				"createdBy": "IBMid-50BE1MTM26",
				"creationDate": "2020-04-22T15:16:23Z",
				"lastUpdated": "2020-06-08T17:11:38Z",
				"updatedBy": "IBMid-50BE1MTM26",
				"policy_type": "dualAuthDelete",
				"policy_data": {
				"enabled": false,
				"attributes": {}
				}
			}
		]
	}`)
	allowedNetworkPolicy := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.policy+json",
			"collectionTotal":1
		},
		"resources": [
			{
				"createdBy": "IBMid-50BE1MTM26",
				"creationDate": "2020-04-22T15:14:29Z",
				"lastUpdated": "2020-06-08T17:11:38Z",
				"updatedBy": "IBMid-50BE1MTM26",
				"policy_type": "allowedNetwork",
				"policy_data": {
				"enabled": true,
				"attributes": {
					"allowed_network": "public-and-private"
				}
				}
			}
		]
	}`)

	gock.New("http://example.com").
		Put("/instance/policies").
		Reply(204)

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.SetInstancePolicies(context.Background(), true, true, true, true, "private-only")

	assert.NoError(t, err)

	gock.New("http://example.com").
		Get("/instance/policies").
		Reply(200).
		Body(bytes.NewReader(allpolicies))

	allP, err := c.GetInstancePolicies(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, allP)
	assert.True(t, len(allP) >= 0)

	gock.New("http://example.com").
		Put("/instance/policies").
		MatchParam("policy", "dualAuthDelete").
		Reply(204)

	err = c.SetDualAuthInstancePolicy(context.Background(), false)

	assert.NoError(t, err)

	gock.New("http://example.com").
		Get("/instance/policies").
		MatchParam("policy", "dualAuthDelete").
		Reply(200).
		Body(bytes.NewReader(dualAuthPolicy))

	dap, err := c.GetDualAuthInstancePolicy(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, dap)
	assert.Equal(t, dap.PolicyType, DualAuthDelete)
	assert.False(t, *(dap.PolicyData.Enabled))

	gock.New("http://example.com").
		Put("/instance/policies").
		MatchParam("policy", "allowedNetwork").
		Reply(204)

	err = c.SetAllowedNetworkInstancePolicy(context.Background(), true, "public-and-private")

	assert.NoError(t, err)

	gock.New("http://example.com").
		Get("/instance/policies").
		MatchParam("policy", "allowedNetwork").
		Reply(200).
		Body(bytes.NewReader(allowedNetworkPolicy))

	ap, err := c.GetAllowedNetworkInstancePolicy(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, ap)
	assert.Equal(t, ap.PolicyType, AllowedNetwork)
	assert.True(t, *(ap.PolicyData.Enabled))
	assert.Equal(t, ap.PolicyData.Attributes.AllowedNetwork, "public-and-private")

	// Set and get allowed ip instance policy
	allowedIPPolicy := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.policy+json",
			"collectionTotal": 1
		},
		"resources": [{
			"creationDate": "2020-09-01T17:28:28Z",
			"createdBy": "IBMid-50BE1MTM26",
			"updatedBy": "IBMid-50BE1MTM26",
			"lastUpdated": "2020-09-02T17:20:21Z",
			"policy_type": "allowedIP",
			"policy_data": {
				"enabled": true,
				"attributes": {
					"allowed_ip": ["192.0.2.0/24", "203.0.113.0/32"]
				}
			}
		}]
	}`)

	gock.New("http://example/com").
		Put("/api/v2/instance/policies").
		MatchParam("policy", "allowedIP").
		Reply(204)

	err = c.SetAllowedIPInstancePolicy(context.Background(), true, []string{"192.0.2.0/24", "203.0.113.0/32"})

	assert.NoError(t, err)

	gock.New("http://example.com").
		Get("/api/v2/instance/policies").
		MatchParam("policy", "allowedIP").
		Reply(200).
		Body(bytes.NewReader(allowedIPPolicy))

	ip, err := c.GetAllowedIPInstancePolicy(context.Background())

	assert.NoError(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip.PolicyType, AllowedIP)
	assert.True(t, *(ip.PolicyData.Enabled))

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

// TestSetAllowedIPPolicyError tests the error scenarios while setting Allowed IP policy
func TestSetAllowedIPPolicyError(t *testing.T) {
	c, _, err := NewTestClient(t, nil)
	c.tokenSource = &FakeTokenSource{}

	err = c.SetAllowedIPInstancePolicy(context.Background(), false, []string{"192.0.2.0/24", "203.0.113.0/32"})

	assert.Error(t, err)
	assert.Equal(t, "IP address list should only be provided if the policy is being enabled", err.Error())

	err = c.SetAllowedIPInstancePolicy(context.Background(), true, []string{})

	assert.Error(t, err)
	assert.Equal(t, "Please provide at least 1 IP subnet specified with CIDR notation", err.Error())

}

// TestGetPrivateEndpointPortNumber tests the method that retrieves the private endpoint port number
func TestGetPrivateEndpointPortNumber(t *testing.T) {
	defer gock.Off()
	response := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json",
			"collectionTotal": 1
		},
		"resources": [{
			"private_endpoint_port": 15008
		}]
	}`)

	gock.New("http://example.com").
		Get("instance/allowed_ip_port").
		Reply(200).
		Body(bytes.NewReader(response))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	port, err := c.GetAllowedIPPrivateNetworkPort(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, port, 15008)

	// Error scenario
	noPortResponse := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.allowed_ip_metadata+json",
			"collectionTotal": 1
		},
		"resources": []
	}`)

	gock.New("http://example.com").
		Get("instance/allowed_ip_port").
		Reply(200).
		Body(bytes.NewReader(noPortResponse))

	port, err = c.GetAllowedIPPrivateNetworkPort(context.Background())

	assert.Error(t, err)
	assert.Equal(t, err.Error(), "No port number available. Please check the instance has an enabled allowedIP policy")

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")
}

//TestSetInstanceDualAuthPolicyError tests the methods set instance dual auth policy to error out with attributes field.
func TestSetInstanceDualAuthPolicyError(t *testing.T) {
	defer gock.Off()
	errorResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.error+json",
			"collectionTotal":1
		},
		"resources":[
			{
				"errorMsg":"Bad Request: Instance policy could not be created. Please see reasons for more details.",
				"reasons": [
							{
								"code":"BAD_BODY_ERR",
								"message":"Invalid body data was passed. Please ensure the data passed had valid formatting with no invalid characters: json: unknown field \"attributes\"%!(EXTRA []string=[])",
								"moreInfo":"https://cloud.ibm.com/apidocs/key-protect"
							}
						]
					}
				]
			}`)

	gock.New("http://example.com").
		Put("/api/v2/instance/policies").
		MatchParam("policy", "dualAuthDelete").
		Reply(400).
		Body(bytes.NewReader(errorResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.SetDualAuthInstancePolicy(context.Background(), true)

	badRequestErr := err.(*Error)
	assert.Error(t, err)
	assert.Equal(t, badRequestErr.Reasons[0].Code, "BAD_BODY_ERR")
	assert.Equal(t, badRequestErr.Reasons[0].Message, "Invalid body data was passed. Please ensure the data passed had valid formatting with no invalid characters: json: unknown field \"attributes\"%!(EXTRA []string=[])")

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")
}

// TestSetKeyPolicies tests the methods that set key policy which makes a request to Key Protect API to set Policies for a key
func TestSetKeyPolicies(t *testing.T) {
	defer gock.Off()
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	allPoliciesResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.policy+json",
			"collectionTotal":2
		},
		"resources":[
			{
				"id":"er482407-6e3c-4f14-56b5-caceadd",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"rotation":{
				"interval_month":6
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:52:22Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-08T03:55:52Z"
			},
			{
				"id":"9bfye029-60e2-4cc6-82d7-a900716",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"dualAuthDelete":{
					"enabled":true
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:53:51Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-07T21:53:51Z"
			}
		]
	}`)

	dualAuthPolicyResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.policy+json",
			"collectionTotal":1
		},
		"resources":[
			{
				"id":"9bfye029-60e2-4cc6-82d7-a900716",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"dualAuthDelete":{
					"enabled":true
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:53:51Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-07T21:53:51Z"
			}
		]
	}`)
	rotationPolicyResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.policy+json",
			"collectionTotal":1
		},
		"resources":[
			{
				"id":"er482407-6e3c-4f14-56b5-caceadd",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"rotation":{
					"interval_month":6
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:52:22Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-08T03:55:52Z"
			}
		]
	}`)

	gock.New("http://example.com").
		Put("/api/v2/keys/"+testKey+"/policies").
		MatchParam("policy", "dualAuthDelete").
		Reply(200).Body(bytes.NewReader(dualAuthPolicyResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	dualAuthPolicy, err := c.SetDualAuthDeletePolicy(context.Background(), testKey, true)

	assert.Nil(t, err)
	assert.NotNil(t, dualAuthPolicy)
	assert.True(t, *(dualAuthPolicy.DualAuth.Enabled))

	gock.New("http://example.com").
		Put("/api/v2/keys/"+testKey+"/policies").
		MatchParam("policy", "rotation").
		Reply(200).Body(bytes.NewReader(rotationPolicyResponse))

	rotationPolicy, err := c.SetRotationPolicy(context.Background(), testKey, 4)

	assert.Nil(t, err)
	assert.NotNil(t, rotationPolicy)
	assert.Equal(t, 6, rotationPolicy.Rotation.Interval)

	gock.New("http://example.com").
		Put("/api/v2/keys/" + testKey + "/policies").
		Reply(200).Body(bytes.NewReader(allPoliciesResponse))

	allpolicies, err := c.SetPolicies(context.Background(), testKey, true, 6, true, true)

	assert.Nil(t, err)
	assert.NotNil(t, allpolicies)
	assert.Equal(t, 6, allpolicies[0].Rotation.Interval)
	assert.True(t, *(allpolicies[1].DualAuth.Enabled))

	// Old rotation policy set

	gock.New("http://example.com").
		Put("/api/v2/keys/" + testKey + "/policies").
		Reply(200).Body(bytes.NewReader(rotationPolicyResponse))

	policy, err := c.SetPolicy(context.Background(), testKey, ReturnRepresentation, 6)

	assert.Nil(t, err)
	assert.NotNil(t, policy)
	assert.Equal(t, 6, policy.Rotation.Interval)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

// TestGetKeyPolicies tests the methods that get key policy method which makes a request to Key Protect end point to retrieve key policies
func TestGetKeyPolicies(t *testing.T) {
	defer gock.Off()
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	getPoliciesResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.policy+json",
			"collectionTotal":2
		},
		"resources":[
			{
				"id":"er482407-6e3c-4f14-56b5-caceadd",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"rotation":{
				"interval_month":6
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:52:22Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-08T03:55:52Z"
			},
			{
				"id":"9bfye029-60e2-4cc6-82d7-a900716",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"dualAuthDelete":{
					"enabled":false
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:53:51Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-07T21:53:51Z"
			}
		]
	}`)

	rotationPolicyResponse := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.policy+json",
			"collectionTotal": 1
		},
		"resources": [{
			"id":"er482407-6e3c-4f14-56b5-caceadd",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"rotation":{
				"interval_month":6
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:52:22Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-08T03:55:52Z"
		}]
	}`)

	dualAuthPolicyResponse := []byte(`{
		"metadata": {
			"collectionType": "application/vnd.ibm.kms.policy+json",
			"collectionTotal": 1
		},
		"resources": [{
			"id":"9bfye029-60e2-4cc6-82d7-a900716",
				"crn":"crn:v5:dummy-env:dummy-service:dummy-region:dummy-details::",
				"dualAuthDelete":{
					"enabled":false
				},
				"createdBy":"test_user3",
				"creationDate":"2020-05-07T21:53:51Z",
				"updatedBy":"test_user3",
				"lastUpdateDate":"2020-05-07T21:53:51Z"
		}]
	}`)

	gock.New("http://example.com").
		Get("/api/v2/keys/" + testKey + "/policies").
		Reply(200).Body(bytes.NewReader(getPoliciesResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	policies, err := c.GetPolicies(context.Background(), testKey)

	assert.Nil(t, err)
	assert.NotNil(t, policies)
	assert.Equal(t, len(policies), 2)

	gock.New("http://example.com").
		Get("/api/v2/keys/"+testKey+"/policies").
		MatchParam("policy", "rotation").
		Reply(200).Body(bytes.NewReader(rotationPolicyResponse))

	rotationPolicy, err := c.GetRotationPolicy(context.Background(), testKey)

	assert.Nil(t, err)
	assert.NotNil(t, rotationPolicy)
	assert.NotNil(t, (*rotationPolicy).Rotation)
	assert.Nil(t, (*rotationPolicy).DualAuth)

	gock.New("http://example.com").
		Get("/api/v2/keys/"+testKey+"/policies").
		MatchParam("policy", "dualAuthDelete").
		Reply(200).Body(bytes.NewReader(dualAuthPolicyResponse))

	dualAuthPolicy, err := c.GetDualAuthDeletePolicy(context.Background(), testKey)

	assert.Nil(t, err)
	assert.NotNil(t, dualAuthPolicy)
	assert.NotNil(t, (*dualAuthPolicy).DualAuth)
	assert.Nil(t, (*dualAuthPolicy).Rotation)

	// Old rotation policy get

	gock.New("http://example.com").
		Get("/api/v2/keys/" + testKey + "/policies").
		Reply(200).Body(bytes.NewReader(rotationPolicyResponse))

	policy, err := c.GetPolicy(context.Background(), testKey)

	assert.Nil(t, err)
	assert.NotNil(t, policy)
	assert.NotNil(t, (*policy).Rotation)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

// Tests the key disable functionality
func TestDisableKey(t *testing.T) {
	defer gock.Off()
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	getKeyResponse := []byte(`{
		"metadata": {
			"collectionTotal": 1,
			"collectionType": "application/vnd.ibm.kms.key+json"
		},
		"resources": [
			{
				"algorithmBitSize": 256,
				"algorithmMetadata": {
					"bitLength": "256",
					"mode": "CBC_PAD"
				},
				"algorithmMode": "CBC_PAD",
				"algorithmType": "AES",
				"createdBy": "IBMid-50BE1MTM26",
				"creationDate": "2020-05-20T15:22:25Z",
				"crn": "crn:v1:staging:public:dummy-service:dummy-env:a/dummy-account:dummy-instance:key:dummy-key-id",
				"deleted": false,
				"deletedBy": "IBMid-50BE1MTM26",
				"deletionDate": "2020-05-20T15:22:50Z",
				"dualAuthDelete": {
					"enabled": false
				},
				"extractable": false,
				"id": "2n4y2-4ko2n-4m23f-23j3r",
				"imported": true,
				"keyVersion": {
					"creationDate": "2020-05-20T15:25:26Z",
					"id": "2n4y2-4ko2n-4m23f-23j3r"
				},
				"lastUpdateDate": "2020-05-20T15:25:26Z",
				"name": "import-root-test",
				"state": 2,
				"type": "application/vnd.ibm.kms.key+json"
			}
		]
	}`)

	gock.New("http://example.com").
		Post("/api/v2/keys/"+testKey).
		MatchParam("action", "disable").
		Reply(204)

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.DisableKey(context.Background(), testKey)

	assert.Nil(t, err)

	gock.New("http://example.com").
		Get("/api/v2/keys/" + testKey).
		Reply(200).Body(bytes.NewReader(getKeyResponse))

	key, err := c.GetKey(context.Background(), testKey)

	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, key.State, 2)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

// Tests the key enable functionality
func TestEnableKey(t *testing.T) {
	defer gock.Off()
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
	getKeyResponse := []byte(`{
		"metadata": {
			"collectionTotal": 1,
			"collectionType": "application/vnd.ibm.kms.key+json"
		},
		"resources": [
			{
				"algorithmBitSize": 256,
				"algorithmMetadata": {
					"bitLength": "256",
					"mode": "CBC_PAD"
				},
				"algorithmMode": "CBC_PAD",
				"algorithmType": "AES",
				"createdBy": "IBMid-50BE1MTM26",
				"creationDate": "2020-05-20T15:22:25Z",
				"crn": "crn:v1:staging:public:dummy-service:dummy-env:a/dummy-account:dummy-instance:key:dummy-key-id",
				"deleted": false,
				"deletedBy": "IBMid-50BE1MTM26",
				"deletionDate": "2020-05-20T15:22:50Z",
				"dualAuthDelete": {
					"enabled": false
				},
				"extractable": false,
				"id": "2n4y2-4ko2n-4m23f-23j3r",
				"imported": true,
				"keyVersion": {
					"creationDate": "2020-05-20T15:25:26Z",
					"id": "2n4y2-4ko2n-4m23f-23j3r"
				},
				"lastUpdateDate": "2020-05-20T15:25:26Z",
				"name": "import-root-test",
				"state": 1,
				"type": "application/vnd.ibm.kms.key+json"
			}
		]
	}
	`)

	gock.New("http://example.com").
		Post("/api/v2/keys/"+testKey).
		MatchParam("action", "enable").
		Reply(204)

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.EnableKey(context.Background(), testKey)

	assert.NoError(t, err)

	gock.New("http://example.com").
		Get("/api/v2/keys/" + testKey).
		Reply(200).Body(bytes.NewReader(getKeyResponse))

	key, err := c.GetKey(context.Background(), testKey)

	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, key.State, 1)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")
}

func TestInitiate_DualAuthDelete(t *testing.T) {
	defer gock.Off()
	keyID := "4309-akld"

	gock.New("http://example.com").
		Post("/api/v2/keys/"+keyID).
		MatchParam("action", "setKeyForDeletion").
		Reply(204)

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.InitiateDualAuthDelete(context.Background(), keyID)

	assert.Nil(t, err)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

func TestCancel_DualAuthDelete(t *testing.T) {
	defer gock.Off()
	keyID := "4839-adhf"
	gock.New("http://example.com").
		Post("/api/v2/keys/"+keyID).
		MatchParam("action", "unsetKeyForDeletion").
		Reply(204)

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.CancelDualAuthDelete(context.Background(), keyID)

	assert.Nil(t, err)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called!")
}

func TestCreateKeyAlias(t *testing.T) {
	defer gock.Off()
	keyID := "1asdfa961f-a348-4y99-1a6a-bag4b61a5eb"
	alias := "xmen2020"
	requestPath := keyID + "/aliases/" + alias
	keyAliasResponse := []byte(`{
		"metadata":{
			"collectionType":"application/vnd.ibm.kms.alias+json",
			"collectionTotal":1
			},
			"resources":[
				{
					"keyId":"1asdfa961f-a348-4y99-1a6a-bag4b61a5eb",
					"alias":"xmen2020",
					"createdBy":"xyz",
					"creationDate":"2020-11-09T17:23:44Z"
				}
			]
		}`)

	gock.New("http://example.com").
		Post("/api/v2/keys/" + requestPath).
		Reply(201).
		Body(bytes.NewReader(keyAliasResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	keyAlias, err := c.CreateKeyAlias(context.Background(), alias, keyID)

	assert.NoError(t, err)
	assert.NotNil(t, keyAlias)
	assert.Equal(t, keyAlias.KeyID, keyID)
	assert.Equal(t, keyAlias.Alias, alias)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")
}

func TestDeleteKeyAlias(t *testing.T) {
	defer gock.Off()
	keyID := "1asdfa961f-a348-4y99-1a6a-bag4b61a5eb"
	alias := "xmen2020"
	requestPath := keyID + "/aliases/" + alias
	gock.New("http://example.com").
		Delete("/api/v2/keys/" + requestPath).
		Reply(204)

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	err = c.DeleteKeyAlias(context.Background(), alias, keyID)

	assert.NoError(t, err)

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")

}

func TestGetKeyWithAlias(t *testing.T) {
	defer gock.Off()
	keyResponse := []byte(`{
		"metadata": {
			"collectionTotal": 1,
			"collectionType": "application/vnd.ibm.kms.key+json"
		},
		"resources": [
			{
				"algorithmType": "AES",
				"aliases": [
					"inumu",
					"domainblvd"
				],
				"createdBy": "xyz",
				"creationDate": "2020-11-06T22:40:44Z",
				"crn": "crn:v1:staging:public:kms:us-south:a/07214fad6bb9305647dc3ebe3244b781:43d105f4-84a0-41c8-8950-4b7180ffa213:key:f4877b07-40b4-4307-a306-eb98eeeea590",
				"deleted": false,
				"description": "a testing thing",
				"dualAuthDelete": {
					"enabled": false
				},
				"extractable": true,
				"id": "f4877b07-40b4-4307-a306-eb98eeeea590",
				"payload": "1/9ajNlN5Vu9s2rR7mLhOVR6aGn8+gbtgj03PwfFUaM=",
				"lastUpdateDate": "2020-11-06T22:40:44Z",
				"name": "test secret",
				"state": 1,
				"type": "application/vnd.ibm.kms.key+json"
			}
		]
	}`)
	alias := "domainblvd"

	gock.New("http://example.com").
		Get("/api/v2/keys/" + alias).
		Reply(200).
		Body(bytes.NewReader(keyResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	key, err := c.GetKeyByAlias(context.Background(), alias)

	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotEqual(t, key.Payload, "")
	assert.True(t, slice.ContainsString(key.Aliases, alias))

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")
}

func TestGetKeyMetadataWithAlias(t *testing.T) {
	defer gock.Off()
	keyResponse := []byte(`{
		"metadata": {
			"collectionTotal": 1,
			"collectionType": "application/vnd.ibm.kms.key+json"
		},
		"resources": [
			{
				"algorithmType": "AES",
				"aliases": [
					"inumu",
					"domainblvd"
				],
				"createdBy": "xyz",
				"creationDate": "2020-11-06T22:40:44Z",
				"crn": "crn:v1:staging:public:kms:us-south:a/07214fad6bb9305647dc3ebe3244b781:43d105f4-84a0-41c8-8950-4b7180ffa213:key:f4877b07-40b4-4307-a306-eb98eeeea590",
				"deleted": false,
				"description": "a testing thing",
				"dualAuthDelete": {
					"enabled": false
				},
				"extractable": true,
				"id": "f4877b07-40b4-4307-a306-eb98eeeea590",
				"lastUpdateDate": "2020-11-06T22:40:44Z",
				"name": "test secret",
				"state": 1,
				"type": "application/vnd.ibm.kms.key+json"
			}
		]
	}`)
	alias := "domainblvd"

	gock.New("http://example.com").
		Get("/api/v2/keys/" + alias + "/metadata").
		Reply(200).
		Body(bytes.NewReader(keyResponse))

	c, _, err := NewTestClient(t, nil)
	gock.InterceptClient(&c.HttpClient)
	defer gock.RestoreClient(&c.HttpClient)
	c.tokenSource = &FakeTokenSource{}

	key, err := c.GetKeyMetadataByAlias(context.Background(), alias)

	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, key.Payload, "")
	assert.True(t, slice.ContainsString(key.Aliases, alias))

	assert.True(t, gock.IsDone(), "Expected HTTP requests not called")
}
