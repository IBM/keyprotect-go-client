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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"strings"
	"time"

	curl "github.com/IBM/go-curl"
)

const (
	DefaultBaseQSCURL = "https://qsc-stage.kms.test.cloud.ibm.com"
)

type QSCAlgorithmType string

const (
	KP_QSC_ALGO_KYBER512       QSCAlgorithmType = "kyber512"
	KP_QSC_ALGO_KYBER768       QSCAlgorithmType = "kyber768"
	KP_QSC_ALGO_KYBER1024      QSCAlgorithmType = "kyber1024"
	KP_QSC_ALGO_p256_KYBER512  QSCAlgorithmType = "p256_kyber512"
	KP_QSC_ALGO_p384_KYBER768  QSCAlgorithmType = "p384_kyber768"
	KP_QSC_ALGO_p521_KYBER1024 QSCAlgorithmType = "p521_kyber1024"
)

// Client QSC Config...
type ClientQSCConfig struct {
	AlgorithmID QSCAlgorithmType // Algorithm ID for the QSC (quantum crypto safe), ignore if used with no tags. Only used when built with `quantum` tags
}

func (qscC ClientQSCConfig) getAlgoID() string {
	return string(qscC.AlgorithmID)
}

func supportedAlgoID(algoID QSCAlgorithmType) bool {

	switch algoID {
	case KP_QSC_ALGO_KYBER512,
		KP_QSC_ALGO_KYBER768,
		KP_QSC_ALGO_KYBER1024,
		KP_QSC_ALGO_p256_KYBER512,
		KP_QSC_ALGO_p384_KYBER768,
		KP_QSC_ALGO_p521_KYBER1024:
		return true
	}
	return false
}

func (qscC ClientQSCConfig) processRequest(ctx context.Context, c *Client, req *http.Request) (*http.Response, error) {

	if c == nil {
		fmt.Println("Internal request processing error. Client parm is nil")
		return nil, errors.New("Internal request processing error. Client parm is nil")
	}

	if req == nil {
		c.Logger.Info("Internal request processing error. Request is nil")
		return nil, errors.New("Internal request processing error. Request is nil")
	}

	if c.QSCConfig == nil {
		c.Logger.Info("Qsc config not set")
		return nil, errors.New("QSC Config not set")
	}

	algorithmID := c.QSCConfig.getAlgoID()

	if algorithmID == "" {
		// Default it
		algorithmID = string(KP_QSC_ALGO_KYBER768)
	} else if !supportedAlgoID(QSCAlgorithmType(algorithmID)) {
		c.Logger.Info("Unsupported Algorithm ID provided. Please refer to the docs for the list of supported algorithms. AlgorithmID Provided:", algorithmID)
		return nil, errors.New("Unsupported Algorithm ID provided. Please refer to the docs for the list of supported algorithms")
	}

	easy := curl.EasyInit()
	defer easy.Cleanup()

	easy.Setopt(curl.OPT_SSLVERSION, curl.SSLVERSION_TLSv1_3)
	easy.Setopt(curl.OPT_CURVES, algorithmID)

	if c.Config.Verbose > 0 {
		easy.Setopt(curl.OPT_VERBOSE, true)
	}

	easy.Setopt(curl.OPT_URL, req.URL.String())

	headers := []string{}

	for name, header := range req.Header {

		// Fix me: header is an array, adding key with multiple values when header has more
		// than one element.
		for _, v := range header {
			h := fmt.Sprintf("%s:%s", name, v)
			headers = append(headers, h)
		}
	}

	// set same headers to easycurl
	easy.Setopt(curl.OPT_HTTPHEADER, headers)

	// set Session Timeout
	easy.Setopt(curl.OPT_TIMEOUT, int(c.Config.Timeout))

	// set Method, Default is GET
	if req.Method == "POST" {
		easy.Setopt(curl.OPT_POST, true)
	} else if req.Method == "DELETE" {
		easy.Setopt(curl.OPT_CUSTOMREQUEST, "DELETE")
	} else if req.Method == "PATCH" {
		easy.Setopt(curl.OPT_CUSTOMREQUEST, "PATCH")
	} else if req.Method == "PUT" {
		easy.Setopt(curl.OPT_CUSTOMREQUEST, "PUT")
	}
	var curlresponse bytes.Buffer
	retryCount := 1
	dataTransferred := 0
	// Note this func is invovked multiple times if data is larger than
	// max size (16K). This functional always return true and errors are handled by checking data transferred.
	// This is because of the way go-curl supports it.
	// TODO: fix go-curl to return error on false. Currently even when false is returned, it returns success.
	easy.Setopt(curl.OPT_WRITEFUNCTION,
		func(ptr []byte, userdata interface{}) bool {
			dataSize := len(string(ptr))
			dataTransferred += dataSize

			if curlresponse.Cap() < (curlresponse.Len() + dataSize) {
				curlresponse.Grow(dataSize)
			}
			writtenSize, err := curlresponse.Write(ptr)
			if err != nil {
				c.Logger.Info(" curl writefunc error writing data ", err.Error())
				curlresponse.Reset()
			}

			if writtenSize != dataSize {
				c.Logger.Info(" curl writefunc cannot write full response", writtenSize, dataSize, curlresponse.Len())
				curlresponse.Reset()
			}

			return true
		})

	if req.Body != nil {
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			c.Logger.Info(err.Error())
			return nil, err
		}
		easy.Setopt(curl.OPT_POSTFIELDS, string(b))
		// Need to write Body back
		req.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	}
	responseHdrs := map[string]string{}
	easy.Setopt(curl.OPT_HEADERFUNCTION,
		func(ptr []byte, userdata interface{}) bool {
			result := strings.Split(string(ptr), ":")

			if len(result) > 1 {
				for i := range result {
					responseHdrs[result[i]] = result[i+1]
					break
				}
			}
			return true
		})
	curlstatusCode := 0

	for {
		err := easy.Perform()
		if err != nil {
			if strings.Contains(err.Error(), "Timeout") {
				// retry
			} else {
				c.Logger.Info("CURL perform error", err.Error())
				return nil, err
			}
		}

		if dataTransferred != curlresponse.Len() {
			return nil, errors.New("response data transfer failed")
		}

		curlCode, err := easy.Getinfo(curl.INFO_RESPONSE_CODE)
		if err != nil {
			c.Logger.Info("CURL failure getting response code error: ", err.Error())
			return nil, err
		}
		curlstatusCode = curlCode.(int)
		//c.Logger.Info("CURL statusCode: ", curlstatusCode)
		// Retry on connection errors, 500+ errors (except 501 - not implemented), and 429 - too many requests
		if !(curlstatusCode == 0 || curlstatusCode == 429 || (curlstatusCode >= 500 && curlstatusCode != 501)) {
			break
		}

		// Reset buffer on retry
		curlresponse.Reset()
		dataTransferred = 0

		if retryCount == RetryMax {
			c.Logger.Info("CURL max retry exceeded, statusCode for last retry: ", curlstatusCode, retryCount, RetryMax)
			break
		}

		c.Logger.Info("CURL performing retry due to statusCode: ", curlstatusCode)
		waitTime := math.Pow(2, float64(retryCount)) * float64(RetryWaitMin)
		sleep := time.Duration(waitTime)
		if sleep > RetryWaitMax {
			sleep = RetryWaitMax
		}
		time.Sleep(sleep)
		retryCount++
	}

	contentlen, err := easy.Getinfo(curl.INFO_CONTENT_LENGTH_DOWNLOAD)
	if err != nil {
		c.Logger.Info("CURL failed getting content length, error: ", err.Error())
		return nil, err
	}

	response := &http.Response{
		StatusCode:    curlstatusCode,
		Proto:         "HTTP/1.1",
		ContentLength: (int64)(contentlen.(float64)),
		Body:          ioutil.NopCloser(bytes.NewBuffer(curlresponse.Bytes())),
		Request:       req,
		Header:        make(http.Header, 0),
	}
	for name, header := range responseHdrs {
		response.Header.Set(name, header)
	}

	return response, err
}
