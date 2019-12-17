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

	"github.com/IBM/keyprotect-go-client/iam"
)

func main() {
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
		fmt.Printf("%+v\n", token)
	}
}
