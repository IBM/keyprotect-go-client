// Copyright 2020 IBM Corp.
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

package keyprotect

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	rhttp "github.com/hashicorp/go-retryablehttp"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type RetryableHTTPClient struct {
	RetryClient *rhttp.Client
}

func NewDefaultHTTPClient() HTTPClient {
	client := &http.Client{
		Timeout: time.Duration(30 * float64(time.Second)),
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	return &RetryableHTTPClient{GetRetryableClient(client)}
}

func (rc *RetryableHTTPClient) Do(req *http.Request) (*http.Response, error) {
	retryableRequest, err := rhttp.FromRequest(req)
	if err != nil {
		return nil, err
	}
	return rc.RetryClient.Do(retryableRequest)
}

var (
	// RetryWaitMax is the maximum time to wait between HTTP retries
	RetryWaitMax = 30 * time.Second

	// RetryMax is the max number of attempts to retry for failed HTTP requests
	RetryMax = 4
)

// GetRetryableClient returns a fully configured retryable HTTP client
func GetRetryableClient(client *http.Client) *rhttp.Client {
	// build base client with the library defaults and override as neeeded
	rc := rhttp.NewClient()
	rc.Logger = nil
	rc.HTTPClient = client
	rc.RetryWaitMax = RetryWaitMax
	rc.RetryMax = RetryMax
	rc.CheckRetry = kpCheckRetry
	rc.ErrorHandler = rhttp.PassthroughErrorHandler
	return rc
}

// kpCheckRetry will retry on connection errors, server errors, and 429s (rate limit)
func kpCheckRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if err != nil {
		return true, err
	}
	// Retry on connection errors, 500+ errors (except 501 - not implemented), and 429 - too many requests
	if resp.StatusCode == 0 || resp.StatusCode == 429 || (resp.StatusCode >= 500 && resp.StatusCode != 501) {
		return true, nil
	}

	return false, nil
}
