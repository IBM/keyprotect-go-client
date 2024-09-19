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

package main

import (
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/IBM/keyprotect-go-client/common"
	"github.com/IBM/keyprotect-go-client/iam"
)

// usage: kp-token
//
// Small CLI utility for outputting an IAM Access Token and metadata to console.
// The output is intended be used with `grep` or `awk` to grab fields and values.
//
// For example, to grab the access token needed for IBM Cloud Authorization headers:
//
//    `kp-token | awk '/AccessToken/ { print $2 }'`
//
// This utility does not cache responses, and will retrieve a new token from IAM
// every call. If you need caching it is suggested to save the token somewhere
// or use a utility with more intelligence.

func main() {
	common.GetComponentInfo()
	apiKey, ok := os.LookupEnv("IBMCLOUD_API_KEY")
	if !ok {
		fmt.Printf("'IBMCLOUD_API_KEY' not set in environment!\n")
		os.Exit(1)
	}

	tokener := iam.CredentialFromAPIKey(apiKey)
	token, err := tokener.Token()
	if err != nil {
		fmt.Printf("%+v\n", err)
	} else {
		v := reflect.ValueOf(*token)
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			switch ft := v.Field(i).Interface().(type) {
			case time.Time:
				fmt.Printf("%-15s %s\n", t.Field(i).Name, ft.Format(time.RFC3339))
			default:
				fmt.Printf("%-15s %s\n", t.Field(i).Name, ft)
			}
		}
	}
}
