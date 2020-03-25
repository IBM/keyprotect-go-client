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

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/IBM/keyprotect-go-client/iam"
	"github.com/IBM/keyprotect-go-client/v1"
)

func Encrypt(source []byte, keyCrns []string, aad string, tokenSource iam.TokenSource) ([]byte, *messageHeader, error) {
	if len(keyCrns) < 1 {
		return nil, nil, errors.New("error: Need at least one Key CRN to encrypt.")
	}

	cfg := keyprotect.LoadDefaultConfig()

	if tokenSource != nil {
		cfg.Credentials = tokenSource
	}

	var dataKeys []dataKey
	var plainKey []byte
	for _, crnString := range keyCrns {
		crn, err := ParseCRN(crnString)
		if err != nil {
			return nil, nil, err
		}

		cfg.Region = crn.Location

		kp := keyprotect.New(cfg)
		resp, err := kp.WrapRequest(&keyprotect.WrapInput{
			InstanceID:     crn.ServiceInstance,
			KeyID:          crn.Resource,
			Plaintext:      plainKey,
			AdditionalData: []string{aad},
		}).Send(nil)

		if err != nil {
			return nil, nil, err
		}

		if len(plainKey) == 0 {
			plainKey = resp.Plaintext
		}

		dataKeys = append(dataKeys, dataKey{KeyCRN: crn.String(), Ciphertext: resp.Ciphertext})
	}

	// sanity check before we move on
	if len(plainKey) != 32 {
		return nil, nil, errors.New("error: KeyProtect Wrap did not return a 32 byte plaintext.")
	}

	// our encryption key is wrapped by all CRNs given, now we can start encrypting

	aesCipher, err := aes.NewCipher(plainKey)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, nil, err
	}

	// generate random IV / nonce, follow 12 byte convention
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	// NOTE(mrodden): go crypto puts the 16 byte tag at the end of the output from Seal
	messageAndTag := aesgcm.Seal(nil, iv, source, []byte(aad))

	header := messageHeader{
		DataKeys:  dataKeys,
		AAD:       aad,
		Algorithm: "AES256-GCM",
	}

	fullMessage := []byte{}
	fullMessage = append(fullMessage, header.pack()...)
	fullMessage = append(fullMessage, iv...)
	fullMessage = append(fullMessage, messageAndTag...)

	return fullMessage, &header, nil
}

func Decrypt(source []byte, tokenSource iam.TokenSource) ([]byte, *messageHeader, error) {
	header, data, err := LoadMessage(source)
	if err != nil {
		return nil, nil, err
	}

	cfg := keyprotect.LoadDefaultConfig()

	if tokenSource != nil {
		cfg.Credentials = tokenSource
	}

	var plaintext []byte
	var lastErr error
	for _, datakey := range header.DataKeys {
		crn, err := ParseCRN(datakey.KeyCRN)
		if err != nil {
			return nil, nil, err
		}

		cfg.Region = crn.Location

		kp := keyprotect.New(cfg)
		resp, err := kp.UnwrapRequest(&keyprotect.UnwrapInput{
			InstanceID:     crn.ServiceInstance,
			KeyID:          crn.Resource,
			Ciphertext:     datakey.Ciphertext,
			AdditionalData: []string{header.AAD},
		}).Send(nil)

		if err == nil {
			plaintext = resp.Plaintext
			break
		} else {
			lastErr = err
			fmt.Fprintf(os.Stderr, "WARNING: Error during unwrap call: %s\n", err)
		}
	}

	if len(plaintext) == 0 {
		return nil, nil, lastErr
	}

	aesCipher, err := aes.NewCipher(plaintext)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, nil, err
	}

	// iv is first 12 bytes of source
	decrypted, err := aesgcm.Open(nil, data[:12], data[12:], []byte(header.AAD))
	if err != nil {
		return nil, nil, err
	}

	// zeroize key data
	for i, _ := range plaintext {
		plaintext[i] = 0x00
	}

	return decrypted, header, nil
}

type messageHeader struct {
	DataKeys  []dataKey `json:"data_keys"`
	AAD       string    `json:"aad"`
	Algorithm string    `json:"algorithm"`
}

type dataKey struct {
	KeyCRN     string `json:"key_crn"`
	Ciphertext []byte `json:"ciphertext"`
}

func LoadMessage(data []byte) (*messageHeader, []byte, error) {
	version := int(data[0])
	if version != 1 {
		return nil, nil, fmt.Errorf("error: unsupported message version=%d", version)
	}

	header_len := binary.BigEndian.Uint64(data[1:9])
	header_bytes := data[9 : header_len+9]

	header_reader := base64.NewDecoder(base64.StdEncoding, bytes.NewBuffer(header_bytes))

	header := &messageHeader{}
	err := json.NewDecoder(header_reader).Decode(header)
	if err != nil {
		return nil, nil, err
	}

	return header, data[header_len+9:], nil
}

func (hdr *messageHeader) pack() []byte {

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	result := &bytes.Buffer{}
	var err error

	var version uint8
	version = 1
	must(binary.Write(result, binary.BigEndian, version))

	headerBuffer := &bytes.Buffer{}
	b64er := base64.NewEncoder(base64.StdEncoding, headerBuffer)
	jsoner := json.NewEncoder(b64er)

	must(jsoner.Encode(hdr))
	b64er.Close()

	var headerLen uint64
	headerLen = uint64(headerBuffer.Len())

	must(binary.Write(result, binary.BigEndian, headerLen))

	_, err = result.ReadFrom(headerBuffer)
	if err != nil {
		panic(err)
	}

	return result.Bytes()
}

type CRN struct {
	Prefix          string
	Version         string
	CName           string
	CType           string
	ServiceName     string
	Location        string
	Scope           string
	ServiceInstance string
	ResourceType    string
	Resource        string
}

func ParseCRN(crnString string) (*CRN, error) {
	parts := strings.Split(crnString, ":")

	if len(parts) != 10 {
		return nil, errors.New("ERROR: CRNs must have 10 parts to be valid.")
	}

	return &CRN{
		Prefix:          parts[0],
		Version:         parts[1],
		CName:           parts[2],
		CType:           parts[3],
		ServiceName:     parts[4],
		Location:        parts[5],
		Scope:           parts[6],
		ServiceInstance: parts[7],
		ResourceType:    parts[8],
		Resource:        parts[9],
	}, nil
}

func (crn CRN) String() string {
	return strings.Join(
		[]string{
			crn.Prefix,
			crn.Version,
			crn.CName,
			crn.CType,
			crn.ServiceName,
			crn.Location,
			crn.Scope,
			crn.ServiceInstance,
			crn.ResourceType,
			crn.Resource,
		},
		":",
	)
}
