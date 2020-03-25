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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"text/template"

	"github.com/IBM/keyprotect-go-client/iam"
	"github.com/google/uuid"
)

type Config struct {
	// Required region name. This is used by the client to select the endpoint
	// that this client will send requests to.
	Region string

	// A required Credential object that the client uses to retrieve IAM access tokens.
	// This sould be an instance of iam.IAMTokenSource unless you have
	// a custom provider.
	Credentials CredentialSource

	// EndpointURL can be used to override the automatic endpoint selection algorithm.
	// This should be set to the base URL of the KeyProtect API.
	// e.g. "https://us-south.kms.cloud.ibm.com/"
	EndpointURL string

	HTTPClient HTTPClient
	Logger     Logger
	LogLevel   LogLevel
}

func LoadDefaultConfig() Config {
	cfg := Config{
		HTTPClient: NewDefaultHTTPClient(),
		Logger:     NewDefaultLogger(),
		LogLevel:   LogOff,
	}

	cfg.Credentials = &EmptyCredential{}
	apikey := os.Getenv("IBMCLOUD_API_KEY")
	if apikey != "" {
		cfg.Credentials = iam.CredentialFromAPIKey(apikey)
	}

	return cfg
}

type CredentialSource interface {
	Token() (*iam.Token, error)
}

type EmptyCredential struct{}

func (e *EmptyCredential) Token() (*iam.Token, error) {
	return nil, errors.New("Empty credential provider cannot return a Token")
}

type LogLevel int

const (
	// No logging will be done by the client
	LogOff = iota * 10

	// All messages will be logged
	LogDebug
)

type Logger interface {
	Log(...interface{})
}

type defaultLogger struct {
	logger *log.Logger
}

func NewDefaultLogger() *defaultLogger {
	return &defaultLogger{
		logger: log.New(os.Stderr, "keyprotect: ", log.LstdFlags),
	}
}

func (l *defaultLogger) Log(args ...interface{}) {
	l.logger.Println(args...)
}

type Client struct {
	Config Config
}

func New(config Config) *Client {
	return &Client{
		Config: config,
	}
}

func (c *Client) EndpointForRegion(region string) string {
	return fmt.Sprintf("https://%s.kms.cloud.ibm.com/", region)
}

type Request struct {
	Config       Config
	HTTPRequest  *http.Request
	HTTPResponse *http.Response
	Error        error
	InData       interface{}
	OutData      interface{}
}

func NewRequest(c *Client, method, path string, in, out interface{}) *Request {
	r := &Request{
		InData:  in,
		OutData: out,
		Config:  c.Config,
	}

	endpoint := c.Config.EndpointURL
	if endpoint == "" {
		endpoint = c.EndpointForRegion(c.Config.Region)
		if endpoint == "" {
			r.Error = fmt.Errorf("No endpoint for region: %s", c.Config.Region)
			return r
		}
	}

	urlValueMap, headerPairs := getRequestParams(in)

	urlBuf := &bytes.Buffer{}
	t := template.Must(template.New("urlPath").Parse(path))
	err := t.Execute(urlBuf, urlValueMap)
	if err != nil {
		r.Error = err
		return r
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		r.Error = err
		return r
	}
	u, err = u.Parse(urlBuf.String())
	if err != nil {
		r.Error = err
		return r
	}

	var reqBody []byte
	var buf io.Reader

	if in != nil {
		reqBody, err = json.Marshal(in)
		if err != nil {
			r.Error = err
			return r
		}
		buf = bytes.NewBuffer(reqBody)
	}

	request, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		r.Error = err
		return r
	}

	request.Header.Set("accept", "application/json")
	for k, v := range headerPairs {
		request.Header.Set(k, v)
	}

	r.HTTPRequest = request

	return r
}

func getRequestParams(in interface{}) (map[string]string, map[string]string) {
	urlPairs := make(map[string]string)
	headerPairs := make(map[string]string)

	// unpack pointer
	inVal := reflect.ValueOf(in).Elem().Interface()

	t := reflect.TypeOf(inVal)
	v := reflect.ValueOf(inVal)
	for i := 0; i < t.NumField(); i++ {
		loc := t.Field(i).Tag.Get("location")
		key := t.Field(i).Tag.Get("locationKey")

		switch loc {
		case "header":
			headerPairs[key] = v.Field(i).String()
		case "url":
			urlPairs[key] = v.Field(i).String()
		}
	}

	return urlPairs, headerPairs
}

func (r *Request) Send(ctx context.Context) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.HTTPRequest = r.HTTPRequest.WithContext(ctx)
	req := r.HTTPRequest

	if r.Error != nil {
		return nil, r.Error
	}

	token, err := r.Config.Credentials.Token()
	if err != nil {
		return nil, err
	}

	// generate our own UUID for the correlation ID and feed it into the request
	// KeyProtect will use this when it is set on a request header rather than generating its
	// own inside the service
	// We generate our own here because a connection error might actually mean the request
	// doesn't make it server side, so having a correlation ID locally helps us know that
	// when comparing with server side logs.
	corrId := uuid.New().String()

	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	req.Header.Set("correlation-id", corrId)

	response, err := r.Config.HTTPClient.Do(r.HTTPRequest)
	r.HTTPResponse = response
	if err != nil {
		return nil, &URLError{err, corrId}
	}
	defer response.Body.Close()

	resBody, err := ioutil.ReadAll(response.Body)

	//redact := []string{c.Config.APIKey, req.Header.Get("authorization")}
	//c.Dump(req, response, []byte{}, resBody, c.Logger, redact)

	if err != nil {
		return nil, err
	}

	type KPErrorMsg struct {
		Message string `json:"errorMsg,omitempty"`
		Reasons []reason
	}

	type KPError struct {
		Resources []KPErrorMsg `json:"resources,omitempty"`
	}

	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated:
		if err := json.Unmarshal(resBody, r.OutData); err != nil {
			return nil, err
		}
	case http.StatusNoContent:
	default:
		errMessage := strings.Trim(string(resBody), " \r\n")
		var reasons []reason

		if strings.Contains(string(resBody), "errorMsg") {
			kperr := KPError{}
			json.Unmarshal(resBody, &kperr)
			if len(kperr.Resources) > 0 && len(kperr.Resources[0].Message) > 0 {
				errMessage = kperr.Resources[0].Message
				reasons = kperr.Resources[0].Reasons
			}
		}

		return nil, &Error{
			URL:           response.Request.URL.String(),
			StatusCode:    response.StatusCode,
			Message:       errMessage,
			BodyContent:   resBody,
			CorrelationID: corrId,
			Reasons:       reasons,
		}
	}

	return response, nil
}

type reason struct {
	Code     string
	Message  string
	Status   int
	MoreInfo string
}

func (r reason) String() string {
	return fmt.Sprintf("%s: %s", r.Code, r.Message)
}

type Error struct {
	URL           string   // URL of request that resulted in this error
	StatusCode    int      // HTTP error code from KeyProtect service
	Message       string   // error message from KeyProtect service
	BodyContent   []byte   // raw body content if more inspection is needed
	CorrelationID string   // string value of a UUID that uniquely identifies the request to KeyProtect
	Reasons       []reason // collection of reason types containing detailed error messages
}

// Error returns correlation id and error message string
func (e Error) Error() string {
	var extraVars string
	if e.Reasons != nil && len(e.Reasons) > 0 {
		extraVars = fmt.Sprintf(", reasons='%s'", e.Reasons)
	}

	return fmt.Sprintf("kp.Error: correlation_id='%v', msg='%s'%s", e.CorrelationID, e.Message, extraVars)
}

// URLError wraps an error from client.do() calls with a correlation ID from KeyProtect
type URLError struct {
	Err           error
	CorrelationID string
}

func (e URLError) Error() string {
	return fmt.Sprintf(
		"error during request to KeyProtect correlation_id='%s': %s", e.CorrelationID, e.Err.Error())
}
