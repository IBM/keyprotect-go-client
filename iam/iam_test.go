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

package iam

import (
	"time"

	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestToken_EmptyAPIKey_ReturnsError(t *testing.T) {

	ts := CredentialFromAPIKey("")

	tok, err := ts.Token()
	assert.Nil(t, tok)
	assert.EqualError(t, err, "iam: APIKey is empty")
}

func TestToken_ValidToken_ReturnsCachedCopy(t *testing.T) {
	defer gock.Off()

	// set the mock to return an error, the code should not
	// be making a request so we shouldn't get an error back
	gock.New(IAMTokenURL).
		Reply(400)

	ts := CredentialFromAPIKey("abc123")

	// set up a token and inject it into the cacher
	expected := &Token{
		AccessToken: "test123",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(5) * time.Minute),
	}
	ts.t = expected

	tok, err := ts.Token()
	assert.NoError(t, err)
	assert.Equal(t, expected, tok)
}

func TestToken_InvalidToken_ReturnsNewToken(t *testing.T) {
	defer gock.Off()
	gock.New(IAMTokenURL).
		Reply(200).
		JSON(jsonToken{
			AccessToken:  "mocktoken",
			RefreshToken: "mockrefresh",
			TokenType:    "Bearer",
			ExpiresIn:    1234,
		})

	ts := CredentialFromAPIKey("abc123")

	// set up an expired token and inject it into the cacher
	invalid := &Token{
		AccessToken: "test123",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-time.Duration(5) * time.Minute),
	}
	ts.t = invalid

	tok, err := ts.Token()
	assert.NoError(t, err)
	assert.NotEqual(t, invalid, tok)
	assert.Equal(t, "mocktoken", tok.AccessToken)
	assert.Equal(t, "mockrefresh", tok.RefreshToken)
}

func TestValid_NotExpired_ReturnsTrue(t *testing.T) {

	tok := &Token{
		AccessToken: "test123",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(5) * time.Minute),
	}

	assert.True(t, tok.Valid(), "tok.Valid() should return true")
}

func TestValid_Expired_ReturnsFalse(t *testing.T) {

	tok := &Token{
		AccessToken: "test123",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-time.Duration(1) * time.Minute),
	}

	assert.False(t, tok.Valid(), "tok.Valid() should return false")
}

func TestValid_EmptyAccessToken_ReturnsFalse(t *testing.T) {

	tok := &Token{
		AccessToken: "",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(5) * time.Minute),
	}

	assert.False(t, tok.Valid(), "tok.Valid() should return false")
}

func TestValid_NilToken_ReturnsFalse(t *testing.T) {
	var tok *Token
	assert.False(t, tok.Valid(), "tok.Valid() should return false")
}
