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

// +build quantum

package kp

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	gock "gopkg.in/h2non/gock.v1"
)

// NewTestClientConfig returns a new ClientConfig suitable for testing.
//
func NewTestClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:     "http://www.google.com/",
		InstanceID:  "test instance id",
		APIKey:      "test api key",
		TokenURL:    "https://iam.cloud.ibm.com/oidc/token",
		AlgorithmID: "kyber768",
		Verbose:     3,
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

// TestCase holds a subtest name and callable.
//
type TestCase struct {
	Name string
	Call func(*testing.T, *API, context.Context) error
}

// TestCases are a slice of TestCase structs.
//
type TestCases []TestCase

// Setup creates and returns an API and a request context.
//
func (cases TestCases) Setup(t *testing.T) (*API, context.Context) {
	api, ctx, err := NewTestClient(t, nil)
	assert.NoError(t, err)
	gock.InterceptClient(&api.HttpClient)
	return api, ctx
}

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

func TestCurl(t *testing.T) {
	var l Logger
	testKey := "2n4y2-4ko2n-4m23f-23j3r"
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

	cases := TestCases{
		{
			"Curl bad response data",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()
				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				// Remove /api/v2 appended to the base url
				u, err := url.Parse(tconfig.BaseURL)
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("GET", "", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Curl Invalid URL",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()
				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)
				req, err := testKpCli.newRequest("GET", "", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Curl invalid algorithm",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()
				tconfig.AlgorithmID = "kyber123"
				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("GET", "/_version", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"curl valid algorithm",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("GET", "/_version", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.NoError(t, err)

				return nil
			},
		},
		{
			"curl no algorithm set",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()
				tconfig.AlgorithmID = ""
				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("GET", "/_version", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.NoError(t, err)

				return nil
			},
		},
		{
			"Curl post request",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("POST", "/_version", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.NoError(t, err)

				return nil
			},
		},
		{
			"Curl delete request",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("DELETE", "/_version", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.NoError(t, err)

				return nil
			},
		},
		{
			"Curl patch request",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("PATCH", "/_version", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.NoError(t, err)

				return nil
			},
		},
		{
			"Curl put request",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("PUT", "/_version", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.NoError(t, err)

				return nil
			},
		},
		{
			"Curl error from KP",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com/api/v2/keys")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("GET", "", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Curl request with request body",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com/api/v2/keys")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("GET", "", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.CreateStandardKey(context.Background(), "testingkeycreate", nil)
				assert.Error(t, err)

				return nil
			},
		},
		{
			"Curl connection timeout retry test",
			func(t *testing.T, api *API, ctx context.Context) error {
				tconfig := NewTestClientConfig()
				tconfig.Timeout = 10

				testKpCli, err := NewWithLogger(tconfig, DefaultTransport(), l)
				assert.NotNil(t, testKpCli)
				assert.NoError(t, err)
				RetryMax = 3

				u, err := url.Parse("https://qsc-stage.kms.test.cloud.ibm.com:444/api/v2/keys")
				assert.NoError(t, err)
				testKpCli.URL = u

				req, err := testKpCli.newRequest("GET", "", nil)
				assert.NoError(t, err)
				assert.NotNil(t, req)
				MockAuth()

				_, err = testKpCli.do(ctx, req, &testKeys)
				assert.Error(t, err)

				return nil
			},
		},
	}
	cases.Run(t)

}
