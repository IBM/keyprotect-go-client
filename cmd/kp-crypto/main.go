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

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	flag "github.com/spf13/pflag"

	kpcrypto "github.com/IBM/keyprotect-go-client/crypto"
)

func Must(err error) {
	if err != nil {
		panic(err)
	}
}

func encrypt(r io.ReadCloser, crnList string) {
	defer r.Close()

	if len(crnList) < 1 {
		crnList = os.Getenv("KPCRYPTO_KEY_CRNS")
	}

	possibleCrns := strings.Split(crnList, " ")
	crns := []string{}

	for _, crn := range possibleCrns {
		if len(crn) > 0 {
			crns = append(crns, crn)
		}
	}

	if len(crns) < 1 {
		fmt.Fprint(os.Stderr, "No key CRNs found for encrypt. Use -k or set KPCRYPTO_KEY_CRNS\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Using Keys:\n  - %s\n", strings.Join(crns, "\n  - "))

	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}

	outBytes, _, err := kpcrypto.Encrypt(bytes, crns, "service='kp-crypto'", nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(outBytes))
}

func decrypt(r io.ReadCloser) {
	defer r.Close()

	bytes, err := ioutil.ReadAll(
		base64.NewDecoder(base64.StdEncoding, r),
	)
	if err != nil {
		panic(err)
	}

	outBytes, _, err := kpcrypto.Decrypt(bytes, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(outBytes))
}

func getReader(inputFile string) io.ReadCloser {
	var reader io.ReadCloser
	if inputFile == "-" {
		reader = os.Stdin
	} else {
		var err error
		reader, err = os.Open(inputFile)
		if err != nil {
			panic(err)
		}
	}
	return reader
}

func main() {

	var crnList string
	flag.StringVarP(&crnList, "key-crns", "k", "", "Space separated list of CRNs identifying which KeyProtect keys to use for encryption")

	var inFile string
	flag.StringVarP(&inFile, "input-file", "f", "-", "Input file path, use '-' for stdin")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] {encrypt,decrypt}\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	args := flag.Args()

	if len(args) > 0 {
		switch args[0] {
		case "encrypt":
			reader := getReader(inFile)
			encrypt(reader, crnList)
			return
		case "decrypt":
			reader := getReader(inFile)
			decrypt(reader)
			return
		}
	}

	flag.Usage()
	return
}
