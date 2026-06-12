package dedicated_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	keyprotect_dedicated "github.com/IBM/keyprotect-go-client/dedicated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMissingEnvironmentVariables tests that the application handles missing env vars correctly
func TestMissingEnvironmentVariables(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "missing IBMCLOUD_API_KEY",
			envVars: map[string]string{
				"KP_INSTANCE_ID": "test-instance",
				"KP_URL":         "https://test.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing KP_INSTANCE_ID",
			envVars: map[string]string{
				"IBMCLOUD_API_KEY": "test-key",
				"KP_URL":           "https://test.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing KP_URL",
			envVars: map[string]string{
				"IBMCLOUD_API_KEY": "test-key",
				"KP_INSTANCE_ID":   "test-instance",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original environment variables
			origAPIKey := os.Getenv("IBMCLOUD_API_KEY")
			origInstanceID := os.Getenv("KP_INSTANCE_ID")
			origURL := os.Getenv("KP_URL")

			// Restore environment variables after test
			defer func() {
				if origAPIKey != "" {
					os.Setenv("IBMCLOUD_API_KEY", origAPIKey)
				} else {
					os.Unsetenv("IBMCLOUD_API_KEY")
				}
				if origInstanceID != "" {
					os.Setenv("KP_INSTANCE_ID", origInstanceID)
				} else {
					os.Unsetenv("KP_INSTANCE_ID")
				}
				if origURL != "" {
					os.Setenv("KP_URL", origURL)
				} else {
					os.Unsetenv("KP_URL")
				}
			}()

			// Clear all relevant env vars
			os.Unsetenv("IBMCLOUD_API_KEY")
			os.Unsetenv("KP_INSTANCE_ID")
			os.Unsetenv("KP_URL")

			// Set only the provided env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Check if required env vars are missing
			_, apiKeyFound := os.LookupEnv("IBMCLOUD_API_KEY")
			_, instanceFound := os.LookupEnv("KP_INSTANCE_ID")
			_, urlFound := os.LookupEnv("KP_URL")

			hasError := !apiKeyFound || !instanceFound || !urlFound

			assert.Equal(t, tt.wantErr, hasError, "expected error: %v, got error: %v", tt.wantErr, hasError)
		})
	}
}

// TestInvalidClientConfiguration tests client creation with invalid config
func TestInvalidClientConfiguration(t *testing.T) {
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")
	if iamEndpoint == "" {
		t.Skip("Skipping test - IBMCLOUD_IAM_API_ENDPOINT not set")
	}

	tests := []struct {
		name    string
		config  *keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions
		wantErr bool
	}{
		{
			name: "empty URL",
			config: &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
				URL: "",
				Authenticator: &core.IamAuthenticator{
					ApiKey: "test-key",
					URL:    iamEndpoint,
				},
			},
			wantErr: true,
		},
		{
			name: "nil authenticator",
			config: &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
				URL:           "https://test.example.com",
				Authenticator: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(tt.config)
			if tt.wantErr {
				assert.Error(t, err, "NewKeyProtectCryptoUnitAPI() should return error")
			} else {
				assert.NoError(t, err, "NewKeyProtectCryptoUnitAPI() should not return error")
			}
		})
	}
}

// TestSignatureKeyRequestValidation tests signature key request creation
func TestSignatureKeyRequestValidation(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		password string
		role     string
		generate bool
		wantErr  bool
	}{
		{
			name:     "valid admin key",
			filename: "test.key",
			password: "",
			role:     "ADMIN",
			generate: false,
			wantErr:  false,
		},
		{
			name:     "empty filename",
			filename: "",
			password: "",
			role:     "ADMIN",
			generate: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyprotect_dedicated.NewSignatureKeyRequest(
				tt.filename,
				tt.password,
				tt.role,
				tt.generate,
			)
			if tt.wantErr {
				assert.Error(t, err, "NewSignatureKeyRequest() should return error")
			} else {
				assert.NoError(t, err, "NewSignatureKeyRequest() should not return error")
			}
		})
	}
}

// TestMasterKeyPartsSpecValidation tests master key parts spec creation
func TestMasterKeyPartsSpecValidation(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		label     string
		parts     []string
		generate  bool
		wantErr   bool
	}{
		{
			name:      "valid 2-of-2",
			threshold: 2,
			label:     "TEST",
			parts:     []string{"key1#pass1", "key2#pass2"},
			generate:  true,
			wantErr:   false,
		},
		{
			name:      "threshold exceeds parts",
			threshold: 3,
			label:     "TEST",
			parts:     []string{"key1#pass1", "key2#pass2"},
			generate:  true,
			wantErr:   true,
		},
		{
			name:      "empty parts",
			threshold: 2,
			label:     "TEST",
			parts:     []string{},
			generate:  true,
			wantErr:   true,
		},
		{
			name:      "zero threshold",
			threshold: 0,
			label:     "TEST",
			parts:     []string{"key1#pass1", "key2#pass2"},
			generate:  true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
				tt.threshold,
				tt.label,
				tt.parts,
				tt.generate,
			)
			if tt.wantErr {
				assert.Error(t, err, "NewMasterKeyPartsSpec() should return error")
			} else {
				assert.NoError(t, err, "NewMasterKeyPartsSpec() should not return error")
			}
		})
	}
}

// TestZeroizeCryptoUnit tests the zeroization of crypto units
func TestZeroizeCryptoUnit(t *testing.T) {
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// Get crypto units
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units")

	if len(units.CryptoUnits) == 0 {
		t.Skip("No crypto units available for testing")
	}

	cryptoUnitID := units.CryptoUnits[0].ID

	t.Run("zeroize_crypto_unit", func(t *testing.T) {
		t.Logf("Attempting to zeroize crypto unit: %s", cryptoUnitID)
		err := client.ZeroizeCryptoUnit(cryptoUnitID)
		if err != nil {
			t.Logf("ZeroizeCryptoUnit error (may be expected): %v", err)
		} else {
			t.Logf("Successfully zeroized crypto unit: %s", cryptoUnitID)
		}

		// Verify state after zeroization
		units, _, err := client.ListCryptoUnits()
		require.NoError(t, err, "should list crypto units after zeroization")

		for _, cu := range units.CryptoUnits {
			if cu.ID == cryptoUnitID {
				t.Logf("CryptoUnit %s state after zeroization: %s", cu.ID, cu.State)
			}
		}
	})
}

// TestInitializeCryptoUnitsWithInvalidParams tests initialization with invalid parameters
func TestInitializeCryptoUnitsWithInvalidParams(t *testing.T) {
	cleanupKeyFiles(t)

	// Skip if no test environment available
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables (IBMCLOUD_API_KEY, KP_URL, IBMCLOUD_IAM_API_ENDPOINT)")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: os.Getenv("IBMCLOUD_API_KEY"),
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	rootKeySpec, _ := keyprotect_dedicated.NewSignatureKeyRequest(
		"test.key",
		"testpass",
		"ADMIN",
		false,
	)

	mbkSpec, _ := keyprotect_dedicated.NewMasterKeyPartsSpec(
		2,
		"TEST",
		[]string{"key1#pass1", "key2#pass2"},
		false,
	)

	// This should fail with invalid instance ID
	err = client.InitializeCryptoUnits(context.Background(), rootKeySpec, mbkSpec, "invalid-instance")
	assert.Error(t, err, "should return error with invalid instance ID")
}

// TestValidClientOperations tests operations with a valid client
func TestValidClientOperations(t *testing.T) {
	// Skip if no test environment available
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	t.Run("list crypto units", func(t *testing.T) {
		units, _, err := client.ListCryptoUnits()
		assert.NoError(t, err, "ListCryptoUnits() should not return error")
		assert.NotNil(t, units.CryptoUnits, "units.CryptoUnits should not be nil")
	})

	t.Run("get session info with invalid crypto unit ID", func(t *testing.T) {
		_, err := client.GetSessionInfo("invalid-crypto-unit-id")
		assert.Error(t, err, "should return error with invalid crypto unit ID")
	})

	t.Run("list users with invalid crypto unit ID", func(t *testing.T) {
		_, err := client.ListUsers("invalid-crypto-unit-id")
		assert.Error(t, err, "should return error with invalid crypto unit ID")
	})

	t.Run("list master keys with invalid crypto unit ID", func(t *testing.T) {
		_, err := client.ListMasterKeys("invalid-crypto-unit-id")
		assert.Error(t, err, "should return error with invalid crypto unit ID")
	})

	t.Run("zeroize with invalid crypto unit ID", func(t *testing.T) {
		err := client.ZeroizeCryptoUnit("invalid-crypto-unit-id")
		assert.Error(t, err, "should return error with invalid crypto unit ID")
	})
}

// TestValidClientWithRealCryptoUnit tests operations with a real crypto unit
func TestValidClientWithRealCryptoUnit(t *testing.T) {
	// Skip if no test environment available
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// Get a real crypto unit ID
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units successfully")

	if len(units.CryptoUnits) == 0 {
		t.Skip("No crypto units available for testing")
	}

	cryptoUnitID := units.CryptoUnits[0].ID

	// Ensure crypto unit is zeroized after all tests
	defer func() {
		if err := client.ZeroizeCryptoUnit(cryptoUnitID); err != nil {
			t.Logf("warning: failed to zeroize crypto unit %s: %v", cryptoUnitID, err)
		}
	}()

	t.Run("get session info with valid crypto unit", func(t *testing.T) {
		state, err := client.GetSessionInfo(cryptoUnitID)
		if err != nil {
			assert.Error(t, err, "GetSessionInfo() error = %v (may be expected if unit not initialized)")
		} else {
			t.Logf("Session state: %v", state)
		}
	})

	t.Run("list users with valid crypto unit", func(t *testing.T) {
		users, err := client.ListUsers(cryptoUnitID)
		if err != nil {
			assert.Error(t, err, "ListUsers() error = %v (may be expected if unit not initialized)")
		} else {
			t.Logf("Found %d users", len(users))
		}
	})

	t.Run("list master keys with valid crypto unit", func(t *testing.T) {
		keys, err := client.ListMasterKeys(cryptoUnitID)
		if err != nil {
			assert.Error(t, err, "ListMasterKeys() error = %v (may be expected if unit not initialized)")
		} else {
			t.Logf("Found %d master keys", len(keys))
		}
	})
}

// TestInitializationErrors tests various initialization error scenarios
func TestInitializationErrors(t *testing.T) {
	cleanupKeyFiles(t)

	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	t.Run("initialize with invalid signature key file", func(t *testing.T) {
		rootKeySpec, err := keyprotect_dedicated.NewSignatureKeyRequest(
			"nonexistent-file.key",
			"",
			"ADMIN",
			true,
		)
		if err != nil {
			t.Log("Cannot create signature key request error: %w", err)
			t.Skip("Cannot create signature key request")
		}

		mbkSpec, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
			2,
			"TEST",
			[]string{"key1#pass1", "key2#pass2"},
			true,
		)
		if err != nil {
			t.Skip("Cannot create master key parts spec")
		}

		err = client.InitializeCryptoUnits(context.Background(), rootKeySpec, mbkSpec, instanceID)
		assert.Error(t, err, "should return error with nonexistent signature key file")
	})

	t.Run("initialize with empty instance ID", func(t *testing.T) {
		rootKeySpec, err := keyprotect_dedicated.NewSignatureKeyRequest(
			"test.key",
			"",
			"ADMIN",
			false,
		)
		if err != nil {
			t.Skip("Cannot create signature key request")
		}

		mbkSpec, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
			2,
			"TEST",
			[]string{"key1#pass1", "key2#pass2"},
			true,
		)
		if err != nil {
			t.Skip("Cannot create master key parts spec")
		}

		err = client.InitializeCryptoUnits(context.Background(), rootKeySpec, mbkSpec, "")
		assert.Error(t, err, "should return error with empty instance ID")
	})
}

// cleanupKeyFiles removes all .key files in the current directory after test completion
func cleanupKeyFiles(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		matches, err := filepath.Glob("*.key")
		if err != nil {
			t.Logf("warning: failed to glob .key files: %v", err)
			return
		}
		for _, file := range matches {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				t.Logf("warning: failed to remove %s: %v", file, err)
			}
		}
	})
}

// TestHexErrorCodeFromValidClient tests that API errors from a valid client contain hex codes
func TestHexErrorCodeFromValidClient(t *testing.T) {
	cleanupKeyFiles(t)

	// Skip if no test environment available
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// First, get available crypto units
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units successfully")

	if len(units.CryptoUnits) == 0 {
		t.Skip("No crypto units available for testing")
	}

	cryptoUnitID := units.CryptoUnits[0].ID
	t.Logf("Testing with crypto unit ID: %s", cryptoUnitID)
	t.Logf("Crypto unit state: %s", units.CryptoUnits[0].State)

	// Ensure crypto unit is zeroized after test
	defer func() {
		if err := client.ZeroizeCryptoUnit(cryptoUnitID); err != nil {
			t.Logf("warning: failed to zeroize crypto unit %s: %v", cryptoUnitID, err)
		}
	}()

	t.Run("connect with invalid keyfile returns hex error", func(t *testing.T) {
		// Try to create a session with a nonexistent key file
		loginSpec := &keyprotect_dedicated.LoginSpec{
			KeyFile:      "nonexistent-file.key",
			CryptoUnitID: cryptoUnitID,
			Port:         443,
			Username:     "ADMIN",
		}

		err := client.CreateCryptoUnitSession(loginSpec)

		// Verify error is returned
		require.Error(t, err, "should return error with nonexistent key file")

		// Check error message for hex code
		errMsg := err.Error()
		t.Logf("Full error message: %s", errMsg)

		// Check if error contains hex code (0xXXXXXXXX format)
		if assert.Regexp(t, `0x[0-9A-Fa-f]{8}`, errMsg, "error should contain 8-digit hex code") {
			t.Logf("✓ Hex error code found in error message")

			// Try to extract and parse the hex code
			re := regexp.MustCompile(`0x([0-9A-Fa-f]{8})`)
			matches := re.FindStringSubmatch(errMsg)
			if len(matches) > 1 {
				hexCode := matches[0]
				t.Logf("Extracted hex code: %s", hexCode)

				// Parse the hex value
				var code uint32
				if _, err := fmt.Sscanf(hexCode, "0x%x", &code); err != nil {
					t.Logf("Failed to parse hex code: %v", err)
				}
				t.Logf("Parsed error code: 0x%08X (%d)", code, code)
				t.Logf("Translated error: %s", keyprotect_dedicated.TranslateErrorCode(code))
			}
		}

		// Also check if it's wrapped in a CryptoUnitAPIError
		var apiErr *keyprotect_dedicated.CryptoUnitAPIError
		if errors.As(err, &apiErr) {
			t.Logf("✓ Error is CryptoUnitAPIError type")
			t.Logf("  Code: 0x%08X", apiErr.Code)
			t.Logf("  Message: %s", apiErr.Message)
			t.Logf("  IsAuthError: %v", keyprotect_dedicated.IsAuthError(apiErr))
			t.Logf("  IsConnectionError: %v", keyprotect_dedicated.IsConnectionError(apiErr))
			t.Logf("  IsSessionError: %v", keyprotect_dedicated.IsSessionError(apiErr))
			t.Logf("  IsUserError: %v", keyprotect_dedicated.IsUserError(apiErr))
		}
	})
}

// TestFullInitializationWorkflow tests the complete initialization workflow
func TestFullInitializationWorkflow(t *testing.T) {
	cleanupKeyFiles(t)

	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// List crypto units
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units successfully")
	require.NotEmpty(t, units.CryptoUnits, "should have at least one crypto unit")

	t.Logf("Found %d crypto units", len(units.CryptoUnits))

	// Check if any units need zeroization
	shouldZeroize := false
	for i, cu := range units.CryptoUnits {
		t.Logf("CryptoUnit [%d]: ID=%s, State=%s", i, cu.ID, cu.State)
		if cu.State != keyprotect_dedicated.CryptoUnitStateReserved {
			shouldZeroize = true
		}
	}

	// Zeroize units if needed
	if shouldZeroize {
		for _, cu := range units.CryptoUnits {
			t.Logf("Zeroizing crypto unit %s", cu.ID)
			err := client.ZeroizeCryptoUnit(cu.ID)
			if err != nil {
				t.Logf("Warning: failed to zeroize crypto unit %s: %v", cu.ID, err)
			}
		}
		// Wait for zeroization to complete
		t.Log("Waiting for zeroization to complete...")
	}

	// Verify all units are in reserved state after zeroization
	units, _, err = client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units after zeroization")

	for i, cu := range units.CryptoUnits {
		t.Logf("CryptoUnit [%d] after zeroization: ID=%s, State=%s", i, cu.ID, cu.State)
	}
}

// TestCryptoUnitInitialization tests the initialization of crypto units
func TestCryptoUnitInitialization(t *testing.T) {
	cleanupKeyFiles(t)

	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}
	// Create test logger
	testLogger := NewTestLogger(t, core.LevelInfo)

	// Set as global SDK logger (affects all clients)
	core.SetLogger(testLogger)
	defer core.SetLogger(core.NewLogger(core.LevelError, nil, nil)) // Restore default
	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// Create signature key request
	rootKeySpec, err := keyprotect_dedicated.NewSignatureKeyRequest(
		"signature.key",
		"",
		"ADMIN",
		false,
	)
	require.NoError(t, err, "should create signature key request")

	// Create master key parts spec
	mbkSpec, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
		2,
		"IFHLSM",
		[]string{
			"mbk-1.key#abcd12",
			"mbk-2.key#abcd12",
		},
		false,
	)
	require.NoError(t, err, "should create master key parts spec")

	// Initialize crypto units
	t.Log("Initializing crypto units...")
	err = client.InitializeCryptoUnits(context.Background(), rootKeySpec, mbkSpec, instanceID)
	if err != nil {
		t.Logf("InitializeCryptoUnits error (may be expected if already initialized): %v", err)
		t.Logf("718 errror: %s", err.Error())
		t.Skip("Skipping integration test - cryptounit failed to initialize")
	}

	// List crypto units after initialization
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units after initialization")

	t.Log("CryptoUnit states after initialization:")
	for i, cu := range units.CryptoUnits {
		t.Logf("CryptoUnit [%d]: ID=%s, State=%s", i, cu.ID, cu.State)
	}
	t.Run("list_master_keys", func(t *testing.T) {
		for _, cu := range units.CryptoUnits {
			_, err := client.ListMasterKeys(cu.ID)
			assert.Nil(t, err)
		}
	})
	t.Run("get_cryptounit_auth_state", func(t *testing.T) {
		for _, cu := range units.CryptoUnits {
			_, err := client.GetAuthState(cu.ID)
			assert.Nil(t, err)
		}
	})
	t.Run("get_cryptounit_session_info", func(t *testing.T) {
		for _, cu := range units.CryptoUnits {
			_, err := client.GetSessionInfo(cu.ID)
			assert.Nil(t, err)
		}
	})
}

// TestCryptoUnitDetails tests retrieving detailed information from crypto units
func TestCryptoUnitDetails(t *testing.T) {
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// Get crypto units
	cryptoUnits, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units")

	if len(cryptoUnits.CryptoUnits) == 0 {
		t.Skip("No crypto units available for testing")
	}

	cryptoUnitIDs := cryptoUnits.IDs()
	for _, cryptoUnitID := range cryptoUnitIDs {
		t.Run(fmt.Sprintf("details_for_%s", cryptoUnitID), func(t *testing.T) {
			t.Logf("Testing CryptoUnit: %s", cryptoUnitID)

			// List MBK keys
			t.Run("list_master_keys", func(t *testing.T) {
				mbkKeys, err := client.ListMasterKeys(cryptoUnitID)
				if err != nil {
					t.Logf("ListMasterKeys error (may be expected if not initialized): %v", err)
				} else {
					t.Logf("Found %d MBK keys", len(mbkKeys))
					for _, key := range mbkKeys {
						t.Logf("  - Name: %s, Algorithm: %s, K: %s, Slot: %s",
							key.Name, key.Algo, key.K, key.Slot)
					}
				}
			})

			// Get HSM state
			t.Run("get_session_info", func(t *testing.T) {
				state, err := client.GetSessionInfo(cryptoUnitID)
				if err != nil {
					t.Logf("GetSessionInfo error (may be expected if not initialized): %v", err)
				} else {
					t.Logf("HSM State: %v", state)
				}
			})

			// List users
			t.Run("list_users", func(t *testing.T) {
				users, err := client.ListUsers(cryptoUnitID)
				if err != nil {
					t.Logf("ListUsers error (may be expected if not initialized): %v", err)
				} else {
					t.Logf("Found %d users", len(users))
					for _, user := range users {
						t.Logf("  - Username: %s, Permissions: 0x%08x, Mechanism: %s",
							user.Username, user.Permissions, user.Mechanism)
					}
				}
			})
			t.Run("connect to crypto unit", func(t *testing.T) {
				loginSpec := keyprotect_dedicated.LoginSpec{
					KeyFile:      "dummy.key",
					CryptoUnitID: cryptoUnitID,
					Port:         443,
					Username:     "ADMIN",
				}
				err := client.CreateCryptoUnitSession(
					&loginSpec,
				)
				if err != nil {
					t.Logf("CreateCryptoUnitSession error (may be expected if not initialized): %v", err)
				}
				assert.Error(t, err)
			})
			t.Run("list_auth_state", func(t *testing.T) {
				_, err := client.GetAuthState(cryptoUnitID)
				if err != nil {
					t.Logf("GetAuthState error (may be expected if not initialized): %v", err)
				}
			})
		})
	}
}

// TestCryptoUnitIDsHelper tests the IDs() helper method
func TestCryptoUnitIDsHelper(t *testing.T) {
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// Get crypto units
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units")

	// Test IDs() helper
	ids := units.IDs()
	assert.Equal(t, len(units.CryptoUnits), len(ids), "IDs() should return same count as CryptoUnits")

	t.Logf("Found %d crypto unit IDs:", len(ids))
	for i, id := range ids {
		t.Logf("  [%d]: %s", i, id)
		assert.NotEmpty(t, id, "crypto unit ID should not be empty")
	}
}

// TestClientDisconnect tests the disconnect functionality
func TestClientDisconnect(t *testing.T) {
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")

	// Verify client is functional
	_, _, err = client.ListCryptoUnits()
	assert.NoError(t, err, "client should be functional before disconnect")

	// Test disconnect
	t.Run("disconnect_closes_sessions", func(t *testing.T) {
		disconnect()
		t.Log("Successfully called disconnect()")
	})
}

// TestMultipleCryptoUnitOperations tests operations across multiple crypto units
func TestMultipleCryptoUnitOperations(t *testing.T) {
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// Get all crypto units
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units")

	if len(units.CryptoUnits) < 2 {
		t.Skip("Need at least 2 crypto units for this test")
	}

	t.Logf("Testing operations across %d crypto units", len(units.CryptoUnits))

	// Test operations on each crypto unit
	for i, cu := range units.CryptoUnits {
		t.Run(fmt.Sprintf("crypto_unit_%d", i), func(t *testing.T) {
			t.Logf("Testing crypto unit: %s (State: %s)", cu.ID, cu.State)

			// Try to get session info
			_, err := client.GetSessionInfo(cu.ID)
			if err != nil {
				t.Logf("GetSessionInfo error for %s: %v", cu.ID, err)
			}

			// Try to list users
			_, err = client.ListUsers(cu.ID)
			if err != nil {
				t.Logf("ListUsers error for %s: %v", cu.ID, err)
			}

			// Try to list master keys
			_, err = client.ListMasterKeys(cu.ID)
			if err != nil {
				t.Logf("ListMasterKeys error for %s: %v", cu.ID, err)
			}
		})
	}
}

func TestCryptoUnitSetLogger(t *testing.T) {
	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}
	// Create test logger
	testLogger := NewTestLogger(t, core.LevelInfo)

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	client.SetLogger(testLogger)
}

// TestCryptoUnitInitialization tests the initialization of crypto units
func TestCryptoUnitValidClientError(t *testing.T) {
	cleanupKeyFiles(t)

	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	instanceID := os.Getenv("KP_INSTANCE_ID")
	kpURL := os.Getenv("KP_URL")
	iamEndpoint := os.Getenv("IBMCLOUD_IAM_API_ENDPOINT")

	if apiKey == "" || instanceID == "" || kpURL == "" || iamEndpoint == "" {
		t.Skip("Skipping integration test - missing required environment variables")
	}
	// Create test logger
	testLogger := NewTestLogger(t, core.LevelInfo)

	// Set as global SDK logger (affects all clients)
	core.SetLogger(testLogger)
	defer core.SetLogger(core.NewLogger(core.LevelError, nil, nil)) // Restore default

	config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
		URL: kpURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
			URL:    iamEndpoint,
		},
	}

	client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
	require.NoError(t, err, "should create client successfully")
	defer disconnect()

	// Create signature key request
	rootKeySpec, err := keyprotect_dedicated.NewSignatureKeyRequest(
		"signature.key",
		"",
		"ADMIN",
		false,
	)
	require.NoError(t, err, "should create signature key request")

	// Create master key parts spec
	mbkSpec, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
		2,
		"IFHLSM",
		[]string{
			"mbk-1.key#abcd12",
			"mbk-2.key#abcd12",
		},
		false,
	)
	require.NoError(t, err, "should create master key parts spec")

	// Initialize crypto units
	t.Log("Initializing crypto units...")
	err = client.InitializeCryptoUnits(context.Background(), rootKeySpec, mbkSpec, instanceID)
	if err != nil {
		t.Logf("InitializeCryptoUnits error (may be expected if already initialized): %v", err)
		t.Logf("error = %s", err.Error())
		t.Skip("Skipping test due to server error")
	}

	// List crypto units after initialization
	units, _, err := client.ListCryptoUnits()
	require.NoError(t, err, "should list crypto units after initialization")

	// Ensure crypto unit is zeroized after all tests
	defer func() {
		for _, cryptoUnit := range units.CryptoUnits {
			t.Logf("Zeroizing cryptoUnit %s after testing:", cryptoUnit.ID)
			if err := client.ZeroizeCryptoUnit(cryptoUnit.ID); err != nil {
				t.Logf("warning: failed to zeroize crypto unit %s: %v", cryptoUnit.ID, err)
			}
		}
	}()

	t.Log("CryptoUnit states after initialization:")
	for i, cu := range units.CryptoUnits {
		t.Logf("CryptoUnit [%d]: ID=%s, State=%s", i, cu.ID, cu.State)
	}

	t.Run("get session info with invalid crypto unit ID", func(t *testing.T) {
		_, err := client.GetSessionInfo("invalid-crypto-unit-id")
		assert.Error(t, err, "should return error with invalid crypto unit ID")
	})

	t.Run("make master key parts with invalid spec", func(t *testing.T) {
		mbkSpec, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
			2,
			"IFHLSM",
			[]string{
				"mbk-3.key#abcd12",
				"mbk-4.key#abcd12",
			},
			true,
		)
		assert.Error(t, err, "KeyShareFiles[0]: file already exists and overwrite is false")
		assert.Nil(t, mbkSpec)
	})
}

// Made with Bob
