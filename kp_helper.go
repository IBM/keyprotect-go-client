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

// +build !quantum

package kp

import (
	"context"
	"net/http"

	rhttp "github.com/hashicorp/go-retryablehttp"
)

func processRequest(ctx context.Context, c *Client, req *http.Request) (*http.Response, error) {

	// set request up to be retryable on 500-level http codes and client errors
	retryableClient := getRetryableClient(&c.HttpClient)
	retryableRequest, err := rhttp.FromRequest(req)
	if err != nil {
		return nil, err
	}

	response, err := retryableClient.Do(retryableRequest.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	return response, nil
}

// getRetryableClient returns a fully configured retryable HTTP client
func getRetryableClient(client *http.Client) *rhttp.Client {
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
