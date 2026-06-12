package dedicated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/keyprotect-go-client/dedicated/common"
)

type KeyProtectCryptoUnitAPI struct {
	Service       *core.BaseService
	instanceID    string
	sessions      *SessionPool       // Map of cryptoUnitID -> sessionID
	usernames     map[string]string  // Map of cryptoUnitID -> username
	authenticator core.Authenticator // Store authenticator for IAM token retrieval
	logger        core.Logger
}

// DefaultServiceURL is the default URL to make service requests to.
const DefaultServiceURL = "https://api.us-south.kms.appdomain.cloud"

// DefaultServiceName is the default key used to find external configuration information.
const DefaultServiceName = "keyprotect-cryptounit-go-sdk"

const DefaultServicePort = 443

var AlternativeServiceURLEnvVars = []string{
	"IBMCLOUD_KP_CRYPTOUNIT_ENDPOINT",
	"KP_TARGET_ADDR",
}

type KeyProtectCryptoUnitAPIOptions struct {
	// Name to call the client
	ServiceName string
	// URL is the full URL of Key Protect instance
	URL string
	// Region of the KMS instance
	Region string
	// ID of the service instance
	InstanceID string
	// Type of endpoint to communicate with the instance
	UsePrivate bool

	Authenticator core.Authenticator
}

func NewKeyProtectCryptoUnitAPIOptions(url string) (*KeyProtectCryptoUnitAPIOptions, error) {
	m, parseErr := parseServiceURL(url)
	if parseErr != nil {
		return nil, parseErr
	}

	options := &KeyProtectCryptoUnitAPIOptions{
		URL: url,
	}
	if options.InstanceID == "" {
		options.InstanceID = m["instance_id"]
	}
	if options.Region == "" {
		options.Region = m["region"]
	}
	if val, ok := m["is_private"]; ok && val != "" {
		options.UsePrivate = true
	}
	return options, nil
}

// NewKeyProtectCryptoUnitAPI creates a KeyProtectCryptoUnitAPI instance. Always call disconnect() when done.
func NewKeyProtectCryptoUnitAPI(options *KeyProtectCryptoUnitAPIOptions) (service *KeyProtectCryptoUnitAPI, disconnect func(), err error) {
	// Initialize the crypto library early to catch platform/library issues immediately
	if initErr := initLibrary(); initErr != nil {
		err = core.SDKErrorf(
			initErr,
			fmt.Sprintf("Your platform %s (%s) does not support cryptounit operations. Rerun on one of the following platforms: linux (amd64), darwin (arm64), windows (amd64).", runtime.GOOS, runtime.GOARCH),
			"library-init-error",
			common.GetComponentInfo(),
		)
		return
	}

	ServiceOptions := &core.ServiceOptions{
		URL:           options.URL,
		Authenticator: options.Authenticator,
	}

	sdkLogger := configureKPCryptoUnitLogger()

	baseService, err := core.NewBaseService(ServiceOptions)
	if err != nil {
		err = core.SDKErrorf(err, "", "new-base-error", common.GetComponentInfo())
		return
	}
	// If the client sets the fully config URL
	if options.URL != "" {
		err = baseService.SetServiceURL(options.URL)
		if err != nil {
			err = core.SDKErrorf(err, "", "set-url-error", common.GetComponentInfo())
			return
		}

		// Parse instance-id and region from URL if not already set
		if options.InstanceID == "" || options.Region == "" {
			opts, optsErr := NewKeyProtectCryptoUnitAPIOptions(options.URL)
			if optsErr != nil {
				err = core.SDKErrorf(err, "", "new-options-error", common.GetComponentInfo())
				return
			}
			sdkLogger.Debug("created the object KeyProtectCryptoUnitAPIOptions: %#v", opts)
			options = opts
		}
	} else if options.Region != "" && options.InstanceID != "" {
		serviceURL, urlErr := GetServiceURLForRegion(options.InstanceID, options.Region, options.UsePrivate)
		if urlErr != nil {
			err = core.SDKErrorf(urlErr, "", "set-region-error", common.GetComponentInfo())
			return
		}
		sdkLogger.Debug("setting the url to %s", serviceURL)
		// Set the default service url constructed from the region
		err = baseService.SetServiceURL(serviceURL)
		if err != nil {
			err = core.SDKErrorf(err, "", "set-url-error", common.GetComponentInfo())
			return
		}
	} else {
		err = core.SDKErrorf(err, "region and instanceID or URL must be specified", "set-url-error", common.GetComponentInfo())
		return
	}

	service = &KeyProtectCryptoUnitAPI{
		Service:       baseService,
		instanceID:    options.InstanceID,
		sessions:      newSessionPool(sdkLogger),
		usernames:     make(map[string]string),
		authenticator: baseService.Options.Authenticator,
		logger:        sdkLogger,
	}
	service.SetDefaultHeaders(http.Header{})
	disconnect = service.DisconnectAll
	return
}

func NewKeyProtectCryptoUnitAPIUsingExternalConfig(options *KeyProtectCryptoUnitAPIOptions) (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI, disconnect func(), err error) {
	if options.ServiceName == "" {
		options.ServiceName = DefaultServiceName
	}

	if options.Authenticator == nil {
		options.Authenticator, err = core.GetAuthenticatorFromEnvironment(options.ServiceName)
		if err != nil {
			err = core.SDKErrorf(err, "", "env-auth-error", common.GetComponentInfo())
			return
		}
	}

	keyProtectCryptoUnitAPI, disconnect, err = NewKeyProtectCryptoUnitAPI(options)
	err = core.RepurposeSDKProblem(err, "new-client-error")
	if err != nil {
		return
	}

	keyProtectCryptoUnitAPI.SetDefaultHeaders(http.Header{})

	err = keyProtectCryptoUnitAPI.Service.ConfigureService(options.ServiceName)
	if err != nil {
		err = core.SDKErrorf(err, "", "client-config-error", common.GetComponentInfo())
		return
	}

	if options.URL != "" {
		err = keyProtectCryptoUnitAPI.Service.SetServiceURL(options.URL)
		err = core.RepurposeSDKProblem(err, "url-set-error")
	}

	// Allow retries
	keyProtectCryptoUnitAPI.Service.EnableRetries(3, 5)
	return
}

// GetServiceURLForRegion returns the service URL to be used for the specified region
func GetServiceURLForRegion(instanceID, region string, private bool) (string, error) {
	endpoints := map[string]struct{}{
		"us-south": {},
		"us-east":  {},
		"eu-de":    {},
	}

	if _, ok := endpoints[region]; ok {
		if private {
			return "https://" + instanceID + ".api.private." + region + ".kms.appdomain.cloud", nil
		} else {
			return "https://" + instanceID + ".api." + region + ".kms.appdomain.cloud", nil
		}
	}
	return "", core.SDKErrorf(nil, fmt.Sprintf("service URL for region '%s' not found", region), "invalid-region", common.GetComponentInfo())
}

// SetDefaultHeaders sets HTTP headers to be sent in every request
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) SetDefaultHeaders(headers http.Header) {
	headers.Add("Instance-ID", keyProtectCryptoUnitAPI.instanceID)
	keyProtectCryptoUnitAPI.Service.SetDefaultHeaders(headers)
}

// GetServiceURL returns the service URL
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetServiceURL() string {
	return keyProtectCryptoUnitAPI.Service.GetServiceURL()
}

// Logger interface for consistent logging across the SDK

// SetLogger allows clients to set a custom logger
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) SetLogger(logger core.Logger) {
	keyProtectCryptoUnitAPI.logger = logger
	if keyProtectCryptoUnitAPI.Service != nil {
		core.SetLogger(logger)
	}
}

// GetLogger returns the current logger
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetLogger() core.Logger {
	return keyProtectCryptoUnitAPI.logger
}

// ************ Crypto Unit Management ************

// CreateCryptoUnitSession establishes a connection to a specific crypto unit and creates a session.
// Multiple crypto units can be connected simultaneously. Each connection is tracked by cryptoUnitID.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) CreateCryptoUnitSession(loginSpec *LoginSpec) error {
	var filepath string
	var passphrase string

	parts := strings.Split(loginSpec.KeyFile, "#")
	if len(parts) > 1 {
		filepath = parts[0]
		passphrase = parts[1]
	} else {
		filepath = parts[0]
		passphrase = ""
	}
	// TODO: validate that the auth file exists
	_, err := keyProtectCryptoUnitAPI.connectCryptoUnit(loginSpec.Username, filepath, passphrase, loginSpec.CryptoUnitID, loginSpec.Port)
	return err
}

func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) connectCryptoUnit(username, keyfile, passphrase, cryptoUnitID string, port int) (uintptr, error) {
	logger := keyProtectCryptoUnitAPI.logger
	if cryptoUnitID == "" {
		return 0, fmt.Errorf("cryptoUnitID is required")
	}

	// Check if already connected to this crypto unit
	if _, exists := keyProtectCryptoUnitAPI.sessions.get(cryptoUnitID); exists {
		return 0, fmt.Errorf("already connected to crypto unit %s", cryptoUnitID)
	}

	// Create session via bridge
	sessionID, err := callCreateSession(
		keyProtectCryptoUnitAPI.Service.GetServiceURL(),
		keyProtectCryptoUnitAPI.instanceID,
		cryptoUnitID,
		username,
		keyfile,
		passphrase,
		port,
		keyProtectCryptoUnitAPI.authenticator,
	)
	if err != nil {
		// Check if it's already a CryptoUnitAPIError and preserve it
		var apiErr *CryptoUnitAPIError
		if errors.As(err, &apiErr) {
			return 0, apiErr
		}
		return 0, fmt.Errorf("failed to connect to crypto unit %s: %w", cryptoUnitID, err)
	}

	// Store the session ID and username mapped to crypto unit ID

	// Ensure that the session is closed if there is an error
	clsSession := func() {
		if clsErr := callCloseSession(sessionID); clsErr != nil {
			logger.Error("error closing session: %s", clsErr)
		}
	}

	session, err := newSession(sessionID, cryptoUnitID, username)
	if err != nil {
		clsSession()
		return 0, err
	}
	if err := keyProtectCryptoUnitAPI.sessions.add(session); err != nil {
		// if there was an error adding to the session pool
		clsSession()
		return 0, err
	}
	keyProtectCryptoUnitAPI.usernames[cryptoUnitID] = username
	keyProtectCryptoUnitAPI.logger.Debug("Connected to cryptounit %s. UserName: %s", cryptoUnitID, username)
	return sessionID, nil
}

// getSessionID returns the session ID for a specific crypto unit.
// Returns an error if not connected to that crypto unit.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) getSessionID(cryptoUnitID string) (uintptr, error) {
	session, exists := keyProtectCryptoUnitAPI.sessions.get(cryptoUnitID)
	if !exists {
		return 0, fmt.Errorf("not connected to crypto unit %s: call ConnectCryptoUnit first", cryptoUnitID)
	}
	return session.id, nil
}

// GetConnectedCryptoUnits returns a list of crypto unit IDs that are currently connected.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetConnectedCryptoUnits() []string {
	return keyProtectCryptoUnitAPI.sessions.GetConnectedCryptoUnits()
}

// Disconnect closes the connection to a specific crypto unit.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) Disconnect(cryptoUnitID string) error {
	// If no crypto unit specified, disconnect all
	if cryptoUnitID == "" {
		err := fmt.Errorf("no cryptounit id was provided '%s'", cryptoUnitID)
		err = core.SDKErrorf(err, "", "cryptounit-disconnect-error", common.GetComponentInfo())
		return err
	}

	// Disconnect specific crypto unit
	err := keyProtectCryptoUnitAPI.sessions.disconnect(cryptoUnitID)
	if err != nil {
		return err
	}
	delete(keyProtectCryptoUnitAPI.usernames, cryptoUnitID)

	keyProtectCryptoUnitAPI.logger.Info(fmt.Sprintf("Disconnected from cryptounit %s\n", cryptoUnitID))
	return nil
}

// Disconnect closes the connection to a specific crypto unit.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) DisconnectAll() {
	cUS := keyProtectCryptoUnitAPI.sessions.GetConnectedCryptoUnits()
	keyProtectCryptoUnitAPI.sessions.disconnectAll()
	for _, cuID := range cUS {
		delete(keyProtectCryptoUnitAPI.usernames, cuID)
	}
}

func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ListCryptoUnits() (cryptounits CryptoUnits, response *core.DetailedResponse, err error) {
	// Implementation will call internal bridge
	return keyProtectCryptoUnitAPI.ListCryptoUnitsWithContext(context.Background())
}

// ListCryptoUnitsWithContext Retrieve the cryptounits available to the instance
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ListCryptoUnitsWithContext(ctx context.Context) (crytounits CryptoUnits, response *core.DetailedResponse, err error) {
	pathParamsMap := map[string]string{}
	logger := keyProtectCryptoUnitAPI.logger
	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	_, err = builder.ResolveRequestURL(keyProtectCryptoUnitAPI.Service.Options.URL, `/api/v1/cryptounits`, pathParamsMap)
	if err != nil {
		err = core.SDKErrorf(err, "", "url-resolve-error", common.GetComponentInfo())
		return
	}

	sdkHeaders := createHeadersfromContext(ctx, "list-crypto-units", keyProtectCryptoUnitAPI.instanceID)
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	logger.Debug("sdkHeaders for ListCryptoUnits")
	for key, val := range sdkHeaders {
		logger.Debug("    %s: %s", key, val)
	}
	request, err := builder.Build()
	if err != nil {
		err = core.SDKErrorf(err, "", "build-error", common.GetComponentInfo())
		return
	}

	var rawResponse *string
	response, err = keyProtectCryptoUnitAPI.Service.Request(request, &rawResponse)
	if err != nil {
		logger.Error("%#v", rawResponse)
		err = core.SDKErrorf(
			err,
			"",
			"request-error",
			common.GetComponentInfo(),
		)
		return
	}

	// The Result field can be a string, *string, or already parsed data
	var cryptoUnitArray []CryptoUnit
	var jsonStr string
	// Handle different types of Result
	switch v := response.Result.(type) {
	case string:
		jsonStr = v

	case *string:
		if v != nil {
			jsonStr = *v
		} else {
			err = core.SDKErrorf(nil, "response.Result is nil", "nil-result-error", common.GetComponentInfo())
			return
		}
	default:
		// Result is some other type - marshal it
		resultBytes, marshalErr := json.Marshal(response.Result)
		if marshalErr != nil {
			err = core.SDKErrorf(marshalErr, "error unmarshalling result", "marshal-result-error", common.GetComponentInfo())
			return
		}
		jsonStr = string(resultBytes)
	}

	// Now unmarshal the JSON string into the array
	err = json.Unmarshal([]byte(jsonStr), &cryptoUnitArray)
	if err != nil {
		err = core.SDKErrorf(err, "encounter problem with listing cryptounits", "unmarshal-error", common.GetComponentInfo())
		return
	}

	// Wrap the array in the CryptoUnits struct
	crytounits = CryptoUnits{
		CryptoUnits: cryptoUnitArray,
	}
	return
}

// ClaimCryptoUnit claims a specific cryptounit using a signature key file
// The signatureKeyPath should point to a file generated by GenerateSignatureKey
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ClaimCryptoUnit(cryptoUnitID string, filepath string) error {
	return keyProtectCryptoUnitAPI.ClaimCryptoUnitWithContext(context.Background(), cryptoUnitID, filepath)
}

// ClaimCryptoUnitWithContext claims a specific cryptounit with context
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ClaimCryptoUnitWithContext(ctx context.Context, cryptoUnitID string, filePath string) error {
	// Detach from the caller's cancellation signal. This operation touches
	// durable HSM state and must not be interrupted mid-flight; values
	// (auth tokens, headers) are still inherited from the parent context.
	ctx = detachContext(ctx)

	// Parse signature key file to extract MOD and PEXP
	modulusHex, exponentHex, err := parseSignatureKeyFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse signature key file: %w", err)
	}

	// Convert RSA key to PKCS1 format
	pem, err := convertRSAKeyToPKCS1(modulusHex, exponentHex)
	if err != nil {
		return fmt.Errorf("failed to convert RSA key to PEM: %w", err)
	}

	// Create claim body
	claimBody, err := convertBytesToClaimBody(pem)
	if err != nil {
		return fmt.Errorf("failed to create claim body: %w", err)
	}

	pathParamsMap := map[string]string{}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)

	_, err = builder.ResolveRequestURL(keyProtectCryptoUnitAPI.Service.Options.URL, `/api/v1/cryptounits/claim`, pathParamsMap)
	if err != nil {
		return core.SDKErrorf(err, "", "url-resolve-error", common.GetComponentInfo())
	}

	// Add headers
	sdkHeaders := createHeadersfromContext(ctx, "claim-cryptounit", keyProtectCryptoUnitAPI.instanceID)
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Crypto-Unit-ID", cryptoUnitID)
	builder.AddHeader("Content-Type", "application/json")

	// Set request body
	_, err = builder.SetBodyContentJSON(claimBody)
	if err != nil {
		return core.SDKErrorf(err, "", "set-json-body-error", common.GetComponentInfo())
	}

	request, err := builder.Build()
	if err != nil {
		return core.SDKErrorf(err, "", "build-error", common.GetComponentInfo())
	}

	response, err := keyProtectCryptoUnitAPI.Service.Request(request, nil)
	if err != nil {
		keyProtectCryptoUnitAPI.logger.Error(
			fmt.Sprintf("Failed to claim cryptounit %s: %v...", cryptoUnitID, response),
		)
		// Extract HTTPProblem from the error chain
		var httpErr *core.HTTPProblem
		if errors.As(err, &httpErr) && httpErr.Response != nil {
			// Check for 500 Internal Server Error
			if httpErr.Response.StatusCode == 500 {
				return fmt.Errorf("failed to claim cryptounit %s: Internal Server Error: %w", cryptoUnitID, err)
			}
		}

		err = fmt.Errorf("failed to claim cryptounit %s: %w", cryptoUnitID, err)
		return err
	}

	return nil
}

// GetSessionInfo retrieves the current state of the HSM Session for a specific cryptounit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetSessionInfo(cryptoUnitID string) (*SessionInfo, error) {
	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return nil, err
	}

	// Get auth state as a proxy for HSM state

	cryptounitID, sessErr := callGetCryptoUnitID(sessionID)
	keyProtectCryptoUnitAPI.logger.Info(
		fmt.Sprintf("cryptounit %s has an existing session", cryptounitID),
	)
	if sessErr != nil {
		return nil, wrapError(sessErr, fmt.Sprintf("failed to get state for cryptounit %s", cryptoUnitID))
	}
	authState, err := callGetAuthState(sessionID)
	if err != nil {
		return nil, wrapError(err, fmt.Sprintf("failed to get state for cryptounit %s", cryptoUnitID))
	}

	// Get username
	username, exists := keyProtectCryptoUnitAPI.usernames[cryptoUnitID]
	if !exists {
		return nil, fmt.Errorf("error obtaining username associated with cryptounit: %s", cryptoUnitID)
	}
	// Validate authState is non-negative before conversion
	if authState < 0 {
		return nil, fmt.Errorf("invalid auth state: %d", authState)
	}
	return &SessionInfo{
		CryptoUnitID: cryptoUnitID,
		UserName:     username,
		AuthState:    uint32(authState),
	}, nil
}

// GetAuthState retrieves the authentication state for a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetAuthState(cryptoUnitID string) (uint32, error) {
	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return 0, err
	}

	authState, err := callGetAuthState(sessionID)
	if err != nil {
		return 0, wrapError(err, fmt.Sprintf("failed to obtain auth state for cryptounit %s", cryptoUnitID))
	}

	// Validate authState is non-negative before conversion
	if authState < 0 {
		return 0, fmt.Errorf("invalid auth state: %d", authState)
	}
	return uint32(authState), nil
}

// ListUsers retrieves the list of users for a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ListUsers(cryptoUnitID string) ([]UserInfo, error) {
	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return nil, err
	}

	result, err := callListUsers(sessionID)
	if err != nil {
		return nil, wrapError(err, fmt.Sprintf("failed to list users for crypto unit %s", cryptoUnitID))
	}

	// Parse the result string into UserInfo array
	// Expected format:
	// Name                                          Permission   Mechanism      Attributes
	// 5d6ea6bf-3fac-4637-8e9f-b6fad5a82976-kp-user   00000002    RSA sign       I[0]A[CXI_GROUP=SLOT_0068]
	// ADMIN                                          22000000    RSA sign       Z[0]

	users := []UserInfo{}
	lines := strings.Split(result, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and header lines
		if line == "" || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "Found") {
			continue
		}

		// Parse the line using regex to handle variable whitespace
		// Pattern: username (spaces) permission (spaces) mechanism (spaces) attributes
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue // Skip malformed lines
		}

		// Extract fields
		username := parts[0]
		permissionStr := parts[1]

		// Parse permission as hex
		var permission uint32
		_, err := fmt.Sscanf(permissionStr, "%x", &permission)
		if err != nil {
			return nil, err
		}

		// Mechanism is the next field(s) - could be "RSA sign" (2 words)
		mechanismStart := 2
		mechanismEnd := mechanismStart

		// Find where attributes start (look for pattern like "I[" or "Z[")
		for i := mechanismStart; i < len(parts); i++ {
			if strings.Contains(parts[i], "[") {
				mechanismEnd = i
				break
			}
			mechanismEnd = i + 1
		}

		mechanism := strings.Join(parts[mechanismStart:mechanismEnd], " ")

		// Parse attributes
		var attributes UserAttributes
		if mechanismEnd < len(parts) {
			attrStr := strings.Join(parts[mechanismEnd:], "")
			attributes = parseUserAttributes(attrStr)
		}

		users = append(users, UserInfo{
			Username:    username,
			Permissions: permission,
			Mechanism:   mechanism,
			Attributes:  attributes,
		})
	}

	return users, nil
}

// parseUserAttributes parses the attribute string like "I[0]A[CXI_GROUP=SLOT_0068]Z[0]H[SHA-256]L[My Label]"
// into a structured UserAttributes object
func parseUserAttributes(attrStr string) UserAttributes {
	attrs := UserAttributes{
		ApplicationAttrs: make(map[string]string),
		FailedAuthCount:  -1, // -1 indicates not set
		AuthState:        -1, // -1 indicates not set
		Raw:              attrStr,
	}

	// Remove all spaces from the attribute string
	attrStr = strings.ReplaceAll(attrStr, " ", "")

	// Parse each attribute type
	i := 0
	for i < len(attrStr) {
		if i >= len(attrStr) {
			break
		}

		// Look for attribute prefix (A, H, Z, L, I)
		attrType := string(attrStr[i])

		// Check if next character is '['
		if i+1 >= len(attrStr) || attrStr[i+1] != '[' {
			i++
			continue
		}

		// Find the closing bracket
		start := i + 2
		end := start
		bracketCount := 1
		for end < len(attrStr) && bracketCount > 0 {
			if attrStr[end] == '[' {
				bracketCount++
			} else if attrStr[end] == ']' {
				bracketCount--
			}
			if bracketCount > 0 {
				end++
			}
		}

		if end >= len(attrStr) {
			break
		}

		value := attrStr[start:end]

		// Parse based on attribute type
		switch attrType {
		case "A":
			// Application attributes: A[CXI_GROUP=SLOT_0068]
			if strings.Contains(value, "=") {
				parts := strings.SplitN(value, "=", 2)
				if len(parts) == 2 {
					attrs.ApplicationAttrs[parts[0]] = parts[1]
				}
			} else {
				attrs.ApplicationAttrs["value"] = value
			}
		case "H":
			// Hash algorithm: H[SHA-256]
			attrs.HashAlgorithm = value
		case "Z":
			// Failed auth count: Z[0]
			if count, err := strconv.Atoi(value); err == nil {
				attrs.FailedAuthCount = count
			}
		case "L":
			// Slot label: L[CryptoServer PKCS11 Token]
			attrs.SlotLabel = value
		case "I":
			// Auth state: I[0] or I[1]
			if state, err := strconv.Atoi(value); err == nil {
				attrs.AuthState = state
			}
		}

		i = end + 1
	}

	return attrs
}

// AddUser adds a new user to a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) AddUser(cryptoUnitID string, req *AddUserRequest) error {
	return keyProtectCryptoUnitAPI.AddUserWithContext(context.Background(), cryptoUnitID, req)
}

// AddUserWithContext adds a new user to a specific crypto unit with context
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) AddUserWithContext(ctx context.Context, cryptoUnitID string, req *AddUserRequest) error {
	sdkHeaders := createHeadersfromContext(ctx, "add-user", keyProtectCryptoUnitAPI.instanceID)
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}

	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return err
	}

	// Call the bridge function
	err = callAddUser(
		sessionID,
		req.Username,
		req.Mechanism,
		req.Token,      // credential
		req.CredHash,   // credHash
		req.Attributes, // attributes (empty for regular AddUser),
		sdkHeaders,
	)
	if err != nil {
		return fmt.Errorf("failed to add user to crypto unit %s: %w", cryptoUnitID, err)
	}

	return nil
}

// AddKMSUser retrieves crypto user metadata from the Key Protect API and adds the user to the specified crypto unit.
// This replicates the behavior of the CLI command: user add --type kmsCryptoUser
//
// The function:
// 1. Fetches crypto user metadata (username, public key, slot ID) from the Key Protect management API
// 2. Converts the PEM-formatted RSA public key to HSM format (MOD/PEXP)
// 3. Creates a temporary file with the converted key
// 4. Adds the user to the HSM with basic permissions and slot-specific attributes
// 5. Returns the updated list of users
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) AddKMSUser(ctx context.Context, cryptoUnitID string) ([]UserInfo, error) {
	// Detach from the caller's cancellation signal. This operation touches
	// durable HSM state and must not be interrupted mid-flight; values
	// (auth tokens, headers) are still inherited from the parent context.
	ctx = detachContext(ctx)

	keyProtectCryptoUnitAPI.logger.Info(
		fmt.Sprintf("Adding KMS User to crypto unit %s...", cryptoUnitID),
	)

	// Step 1: Get crypto user metadata from Key Protect API
	metadata, err := keyProtectCryptoUnitAPI.getCryptoUserMetadataWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto user metadata: %w", err)
	}

	// Step 2: Convert PEM public key to RSA format (MOD/PEXP)
	rsaKey, err := convertPEMToRSAFormat(metadata.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PEM to RSA format: %w", err)
	}

	// Step 3: Create temporary file for the RSA key
	tmpFile, err := os.CreateTemp("", "rsapub-*.key")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(rsaKey); err != nil {
		return nil, fmt.Errorf("failed to write RSA key to temp file: %w", err)
	}
	if err := tmpFile.Chmod(0o644); err != nil {
		return nil, fmt.Errorf("failed to set file permissions: %w", err)
	}
	tmpFile.Close() // Close before using in credential

	// Step 4: Calculate credential hash (SHA-256 of public key)
	credHash := fmt.Sprintf("%x", sha256Hash(metadata.PublicKey))

	// Step 5: Add user with KMS crypto user settings
	credential := fmt.Sprintf("%s#", tmpFile.Name()) // Format: filepath#passphrase (empty passphrase)
	userType := "kmsCryptoUser"                      // This constant is converted to "kms_crypto_user" by library layer

	// Format slot ID as SLOT_XXXX (4 digits, zero-padded)
	// The attributes are passed as a semicolon-separated string of key=value pairs
	attributes := fmt.Sprintf("CXI_GROUP=SLOT_%04d", metadata.SlotID)

	// Step 6: Get session ID
	req := AddUserRequest{
		Username:   metadata.Username,
		Mechanism:  userType,
		Token:      credential,
		CredHash:   credHash,
		Attributes: attributes,
	}
	if err := keyProtectCryptoUnitAPI.AddUserWithContext(ctx, cryptoUnitID, &req); err != nil {
		return nil, err
	}

	// Step 7: Return updated user list
	return keyProtectCryptoUnitAPI.ListUsers(cryptoUnitID)
}

// DeleteUser removes a user from a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) DeleteUser(cryptoUnitID string, username string) error {
	return keyProtectCryptoUnitAPI.DeleteUserWithContext(context.Background(), cryptoUnitID, username)
}

// DeleteUserWithContext removes a user from a specific crypto unit with context
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) DeleteUserWithContext(ctx context.Context, cryptoUnitID string, username string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}

	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return err
	}

	err = callDeleteUser(sessionID, username)
	if err != nil {
		return fmt.Errorf("failed to delete user from crypto unit %s: %w", cryptoUnitID, err)
	}

	return nil
}

// GenerateSignatureKey generates an RSA signature key and saves it to a file.
//
// IMPORTANT: This is a LOCAL operation that does NOT require a connected session.
// The key is generated locally by the library and saved to the specified file path.
// This operation does not communicate with the HSM server.
//
// Parameters:
//   - instanceID: The ID of the Key Protect instance (not the crypto unit ID)
//   - req: Request containing file path, optional passphrase, and algorithm
//
// Returns:
//   - error: nil on success, error describing the failure otherwise
//
// Example:
//
//	// Generate signature key (no connection required)
//	req := &GenerateSignatureKeyRequest{
//	    FilePath:   "signature.key",
//	    Passphrase: "",
//	    Algorithm:  SigKeyAlgorithmRSA2048,
//	    Owner:      "admin",
//	}
//	err = client.GenerateSignatureKey(instanceID, req)
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GenerateSignatureKey(instanceID string, req *SignatureKeyRequest) error {
	// Validate request
	if err := validateSignatureKeyRequest(req); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	// Extract key size from algorithm (e.g., "RSA-2048" -> "2048")
	keySizeBits := uint32(2048)

	// Call bridge layer to generate key using instance ID (no session required)
	// This is a local operation that doesn't communicate with the HSM
	respData, err := callGenerateSignatureKeyStatic(
		instanceID,
		req.FilePath,
		keySizeBits,
		req.Passphrase,
		req.Owner,
	)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	// Verify file was created
	if _, statErr := os.Stat(req.FilePath); statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("key generation failed: file was not created at %s", req.FilePath)
		}
		return fmt.Errorf("key generation failed: unable to verify file creation: %w", statErr)
	}

	// Log success (respData contains generation details)
	_ = respData // Use response data if needed for logging

	return nil
}

// GetAuditLog retrieves the audit log for a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetAuditLog(cryptoUnitID string) (*AuditLog, error) {
	_, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return nil, err
	}

	// This would require additional bridge implementation
	return nil, fmt.Errorf("audit log retrieval not yet implemented in bridge layer")
}

// ListMasterKeys lists the Master Backup Keys for a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ListMasterKeys(cryptoUnitID string) ([]MasterKeyInfo, error) {
	return keyProtectCryptoUnitAPI.ListMasterKeysWithContext(context.Background(), cryptoUnitID)
}

// ListMasterKeysWithContext lists the Master Backup Keys for a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ListMasterKeysWithContext(ctx context.Context, cryptoUnitID string) ([]MasterKeyInfo, error) {
	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return nil, err
	}

	result, err := callListMasterKeys(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list Master keys for crypto unit %s: %w", cryptoUnitID, err)
	}

	// Parse the table format result
	keys, parseErr := parseMasterKeyListOutput(result)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse Master list output: %w", parseErr)
	}

	return keys, nil
}

// GenerateMasterKey generates a Master Backup Key for a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GenerateMasterKey(cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) (string, error) {
	return keyProtectCryptoUnitAPI.GenerateMasterKeyWithContext(context.Background(), cryptoUnitID, mbkSpec)
}

// GenerateMasterKeyWithContext generates a Master Backup Key for a specific crypto unit
// This function creates a new Master Key with the specified parameters including threshold (N/K) scheme
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GenerateMasterKeyWithContext(ctx context.Context, cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) (string, error) {
	// Detach from the caller's cancellation signal. This operation touches
	// durable HSM state and must not be interrupted mid-flight; values
	// (auth tokens, headers) are still inherited from the parent context.
	ctx = detachContext(ctx)

	if err := validateMasterKeyPartsSpec(mbkSpec); err != nil {
		return "", fmt.Errorf("invalid MasterKeyPartSpec: %w", err)
	}

	// Pad keyname to exactly 8 characters with spaces if shorter (matches CLI behavior)
	keyname := mbkSpec.KeyName
	if len(keyname) < 8 {
		keyname = keyname + strings.Repeat(" ", 8-len(keyname))
	}

	// Validate length before conversion
	if len(mbkSpec.KeyShareFiles) > 255 {
		return "", fmt.Errorf("too many key share files: %d (max 255)", len(mbkSpec.KeyShareFiles))
	}
	// #nosec G115 - Length is validated to be <= 255 before conversion
	n := uint8(len(mbkSpec.KeyShareFiles))
	// Construct the command
	// Note: Swapping N and K to match CLI semantics:
	// - CLI: n = total parts, k = threshold
	// - Our API: N = total parts, K = threshold
	// - C function expects: n = total parts, k = threshold
	request := &MasterKeyRequest{
		KeySpec:   strings.Join(mbkSpec.KeyShareFiles, ","),
		KeyType:   "AES",
		KeyLength: 32,
		N:         n,
		K:         mbkSpec.K, // threshold (minimum needed)
		KeyName:   keyname,
	}
	res, err := keyProtectCryptoUnitAPI.generateMasterKeyHelper(ctx, cryptoUnitID, request)
	if err != nil {
		return "", fmt.Errorf("failed to generate Master Key for crypto unit %s: %w", cryptoUnitID, err)
	}
	// Set file permissions for all generated keyshare files
	for _, keySpecName := range mbkSpec.KeyShareFiles {
		// Extract filename (before the # passphrase)
		parts := strings.Split(keySpecName, "#")
		if len(parts) > 0 {
			filename := parts[0]
			if err := os.Chmod(filename, 0o644); err != nil {
				return "", fmt.Errorf("failed to set permissions on %s: %w", filename, err)
			}
		}
	}
	return res, nil
}

// ImportMasterKey is a convenience wrapper around ImportMasterKeyWithContext)
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ImportMasterKey(cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) error {
	return keyProtectCryptoUnitAPI.ImportMasterKeyWithContext(context.Background(), cryptoUnitID, mbkSpec)
}

// ImportMasterKeyWithContext is the context-aware version of ImportMaster Key
// It allows for better control over timeouts and cancellation
// Parameters:
//   - ctx: Context for controlling timeouts and cancellation
//   - cryptoUnitID: The ID of the crypto unit to import the Master Key to
//   - request: ImportMaster KeyRequest containing the key specifications and slot number
//
// Returns:
//   - string: Response data from the import operation
//   - error: Any error that occurred during the import
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	result, err := client.ImportMasterKeyWithContext(ctx, cryptoUnitID, importRequest)
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ImportMasterKeyWithContext(ctx context.Context, cryptoUnitID string, request *MasterKeyPartsSpec) error {
	// Detach from the caller's cancellation signal. This operation touches
	// durable HSM state and must not be interrupted mid-flight; values
	// (auth tokens, headers) are still inherited from the parent context.
	ctx = detachContext(ctx)

	logger := keyProtectCryptoUnitAPI.logger
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}

	// Validate required parameters
	if len(request.KeyShareFiles) == 0 {
		return fmt.Errorf("KeyShareFiles is required and cannot be empty")
	}
	if request.SlotNo < 0 {
		return fmt.Errorf("SlotNo must be non-negative")
	}

	// Default SlotNo to 3 if not set
	slotNo := request.SlotNo
	if slotNo == 0 {
		slotNo = 3
	}

	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return err
	}
	sdkHeaders := createHeadersfromContext(ctx, "import-master-key", keyProtectCryptoUnitAPI.instanceID)
	logger.Debug("sdkHeaders for ImportMasterKey = ")
	for key, val := range sdkHeaders {
		logger.Debug("    %s: %s", key, val)
	}

	// Join the KeyShareFiles slice to comma-separated string
	keyspec := strings.Join(request.KeyShareFiles, ",")

	// Check if files exist
	for _, file := range request.KeyShareFiles {
		parts := strings.Split(file, "#")
		if len(parts) > 0 {
			if _, err := os.Stat(parts[0]); os.IsNotExist(err) {
				return fmt.Errorf("failed to find file: %s", parts[0])
			}
		}
	}
	// Pass the comma-separated string to the C func
	err = callImportMasterKey(
		sessionID,
		keyspec, // Pass as comma-separated: "file1.key#pwd1,file2.key#pwd2,file3.key#pwd3"
		slotNo,
		sdkHeaders,
	)
	if err != nil {
		return wrapError(err, fmt.Sprintf("failed to import Master Key for crypto unit %s", cryptoUnitID))
	}

	return nil
}

// ImportMasterKeyToCryptoUnits imports an Master Key to multiple crypto units concurrently using goroutines
// and returns the results for each crypto unit. This function is useful when you need to import
// the same MasterKeyPartsSpec configuration to multiple crypto units in parallel.
//
// Parameters:
//   - cryptoUnitIDs: List of crypto unit IDs to import the Master Key to
//   - request: The ImportMaster KeyRequest containing the Master Key configuration
//
// Returns:
//   - []ImportMaster KeyResult: A slice containing the result for each crypto unit, including any errors
//
// Example:
//
//	cryptoUnitIDs := []string{"cu-1", "cu-2", "cu-3"}
//	request := &ImportMaster KeyRequest{
//	    KeyShareFiles: []string{"key1.key#pass1", "key2.key#pass2"},
//	    SlotNo: 3,
//	}
//	results := client.ImportMasterKeyToCryptoUnits(cryptoUnitIDs, request)
//	for _, result := range results {
//	    if result.Error != nil {
//	        fmt.Printf("Failed to import Master Key to %s: %v\n", result.CryptoUnitID, result.Error)
//	    } else {
//	        fmt.Printf("Successfully imported Master Key to %s: %s\n", result.CryptoUnitID, result.Result)
//	    }
//	}
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ImportMasterKeyToCryptoUnits(ctx context.Context, cryptoUnitIDs []string, request *MasterKeyPartsSpec) error {
	// Detach from the caller's cancellation signal. This operation touches
	// durable HSM state and must not be interrupted mid-flight; values
	// (auth tokens, headers) are still inherited from the parent context.
	ctx = detachContext(ctx)

	// Create a channel to collect results
	logger := keyProtectCryptoUnitAPI.logger
	var allErrs error

	// Launch a goroutine for each crypto unit
	for _, cryptoUnitID := range cryptoUnitIDs {
		keyProtectCryptoUnitAPI.logger.Info(
			fmt.Sprintf("Importing Master Key to crypto unit %s...", cryptoUnitID),
		)
		err := keyProtectCryptoUnitAPI.ImportMasterKeyWithContext(ctx, cryptoUnitID, request)
		if err != nil {
			logger.Error("error from import masterkey to cryptounit %s: %s", cryptoUnitID, err.Error())
			allErrs = errors.Join(allErrs, fmt.Errorf("import master key to cryptounit %s failed: %w", cryptoUnitID, err))
		}
	}

	return allErrs
}

// InitializeCryptoUnits provisions every crypto unit belonging to instanceID
// through the full 7-step initialization pipeline.
//
// Each step is guarded by the live CryptoUnitState returned from
// ListCryptoUnitsWithContext, so the function is safe to call after a
// partial failure: it will resume from wherever each individual unit was
// left off, and it will bring lagging units up to the same state as the
// most-advanced units (catch-up).
//
// Step ordering and the states they produce:
//
//  1. ListCryptoUnitsWithContext   → determines per-unit resume point
//  2. GenerateSignatureKey         → local file (skipped when skr.Exists)
//  3. ClaimCryptoUnitWithContext   → state: claimed
//  4. createSessions (HSM login)
//  5. AddKMSUser                   → state: kms-authorized
//  6. GenerateMasterKeyWithContext → local file (skipped when mbkspec.Exists)
//  7. ImportMasterKeyToCryptoUnits → state: initialized / kms-initialized
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) InitializeCryptoUnits(ctx context.Context, skr *SignatureKeyRequest, mbkspec *MasterKeyPartsSpec, instanceID string) error {
	// Detach from the caller's cancellation signal. This operation touches
	// durable HSM state and must not be interrupted mid-flight; values
	// (auth tokens, headers) are still inherited from the parent context.
	ctx = detachContext(ctx)

	logger := keyProtectCryptoUnitAPI.logger
	sdkHeaders := common.GetSdkHeaders(DefaultServiceName, "v1", "InitializeCryptoUnits")
	logger.Debug("sdkHeaders=%v", sdkHeaders)
	ctx = withHeaders(ctx, sdkHeaders)

	// ── Step 1: Discover the current state of every crypto unit ───────────────
	// The live state is the authoritative source for which steps each unit
	// still needs.  We always re-fetch here so that a retry after a partial
	// failure picks up where the HSM left off.  Placing this first lets the
	// remaining steps (including key generation) be skipped or conditioned on
	// the actual HSM state.
	cryptoUnits, _, err := keyProtectCryptoUnitAPI.ListCryptoUnitsWithContext(ctx)
	if err != nil {
		return fmt.Errorf("step 1 – list crypto units: %w", err)
	}
	if len(cryptoUnits.CryptoUnits) == 0 {
		return fmt.Errorf("step 1 – no crypto units found for instance %s", instanceID)
	}

	for i, cu := range cryptoUnits.CryptoUnits {
		logger.Info("step 1 – crypto unit [%d]: id=%s state=%s", i, cu.ID, cu.State)
	}

	// Determine the earliest step that still needs to run across ALL units.
	// A unit that is "behind" the others will pull the minimum down, ensuring
	// the lagging unit is caught up before the pipeline advances.
	startStep := instanceStartStep(cryptoUnits.CryptoUnits)
	logger.Info("step 1 – instance resume point: step %d", startStep)

	// ── Step 2: Generate the admin signature key (local operation) ────────────
	// Skipped when the caller already has a key on disk (skr.Exists == true).
	if !skr.Exists {
		if err := keyProtectCryptoUnitAPI.GenerateSignatureKey(keyProtectCryptoUnitAPI.instanceID, skr); err != nil {
			return fmt.Errorf("step 2 – generate signature key: %w", err)
		}
		logger.Info("step 2 – signature key generated: %s", skr.FilePath)
	} else {
		logger.Info("step 2 – attempting to use signature key specified: %s", skr.FilePath)
	}
	// ── Step 3: Claim each unit that has not yet been claimed ─────────────────
	// Per-unit guard: only units in available/reserved state need claiming.
	// Units already at claimed/kms-authorized/initialized are skipped.
	if startStep <= StepClaimUnits {
		for _, cu := range cryptoUnits.CryptoUnits {
			cuStep := cryptoUnitStartStep(cu)
			if cuStep > StepClaimUnits {
				logger.Info("step 3 – skipping claim for unit %s (state=%s, already claimed)", cu.ID, cu.State)
				continue
			}
			if err := keyProtectCryptoUnitAPI.ClaimCryptoUnitWithContext(ctx, cu.ID, skr.FilePath); err != nil {
				var apiErr *CryptoUnitAPIError
				if errors.As(err, &apiErr) {
					// return apiErr
					logger.Error("failed to claim cryptounit %s: %v", err)
				}
				return fmt.Errorf("step 3 – claim crypto unit %s: %w", cu.ID, err)
			}
			logger.Info("step 3 – claimed crypto unit %s", cu.ID)
		}
	} else {
		logger.Info("step 3 – skipping claim phase (all units already at state ≥ claimed)")
	}

	// ── Step 4: Open HSM sessions for every unit ──────────────────────────────
	// Sessions are process-local and ephemeral — they are never persisted across
	// process restarts.  Steps 5, 6, and 7 all issue HSM commands that require
	// an active session, so this step is UNCONDITIONAL: it runs whenever the
	// pipeline reaches it, regardless of how far the units progressed on a
	// previous run.  There is no state on the HSM that records "a session was
	// previously opened", so startStep can never skip past this point.
	if startStep <= StepImportMBK {
		if _, err := keyProtectCryptoUnitAPI.createSessions(ctx, cryptoUnits, skr.FilePath); err != nil {
			return fmt.Errorf("step 4 – create sessions: %w", err)
		}
	}

	// ── Step 5: Add KMS user to each unit that is not yet kms-authorized ──────
	// Per-unit guard: units already at kms-authorized or beyond are skipped.
	if startStep <= StepAddKMSUser {
		for _, cu := range cryptoUnits.CryptoUnits {
			cuStep := cryptoUnitStartStep(cu)
			if cuStep > StepAddKMSUser {
				logger.Info("step 5 – skipping AddKMSUser for unit %s (state=%s)", cu.ID, cu.State)
				continue
			}
			if _, err := keyProtectCryptoUnitAPI.AddKMSUser(ctx, cu.ID); err != nil {
				return fmt.Errorf("step 5 – add KMS user for crypto unit %s: %w", cu.ID, err)
			}
			logger.Info("step 5 – KMS user added to crypto unit %s", cu.ID)
		}
	} else {
		logger.Info("step 5 – skipping AddKMSUser phase (all units already kms-authorized or beyond)")
	}

	// ── Step 6: Generate the Master Key parts (local operation) ───────────────
	// Only one unit is used as the generation source; the key is then
	// distributed in Step 7.  Skipped when the caller already has key share
	// files on disk (mbkspec.Exists == true).
	if startStep <= StepGenerateMBK {
		if !mbkspec.Exists {
			baseCryptoUnitID := cryptoUnits.CryptoUnits[0].ID
			str, err := keyProtectCryptoUnitAPI.GenerateMasterKeyWithContext(ctx, baseCryptoUnitID, mbkspec)
			if err != nil {
				return fmt.Errorf("step 6 – generate master key: %w", err)
			}
			logger.Info("step 6 – master key generated: %v", str)
		} else {
			logger.Info("step 6 – using pre-existing master key parts for KMS instance: %s", instanceID)
		}
	} else {
		logger.Info("step 6 – skipping master key generation (all units already past kms-authorized)")
	}

	// ── Step 7: Import the Master Key to every unit that needs it ─────────────
	// Per-unit guard: only units not yet initialized receive the import.
	if startStep <= StepImportMBK {
		// Build the list of unit IDs that still need the MBK imported.
		// Units at initialized/kms-initialized are excluded so that an
		// already-commissioned unit is never overwritten.
		var pendingIDs []string
		for _, cu := range cryptoUnits.CryptoUnits {
			if cryptoUnitStartStep(cu) <= StepImportMBK {
				pendingIDs = append(pendingIDs, cu.ID)
			} else {
				logger.Info("step 7 – skipping MBK import for unit %s (state=%s, already initialized)", cu.ID, cu.State)
			}
		}
		if len(pendingIDs) > 0 {
			if err := keyProtectCryptoUnitAPI.ImportMasterKeyToCryptoUnits(ctx, pendingIDs, mbkspec); err != nil {
				return fmt.Errorf("step 7 – import master key: %w", err)
			}
		}
	} else {
		logger.Info("step 7 – skipping MBK import (all units already initialized)")
	}

	logger.Info("KMS instance %s is ready to use", instanceID)
	return nil
}

// ZeroizeCryptoUnit will erase all data for a specific crypto unit
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ZeroizeCryptoUnit(cryptoUnitID string) error {
	return keyProtectCryptoUnitAPI.ZeroizeCryptoUnitWithContext(context.Background(), cryptoUnitID)
}

func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) ZeroizeCryptoUnitWithContext(ctx context.Context, cryptoUnitID string) error {

	if err := keyProtectCryptoUnitAPI.Disconnect(cryptoUnitID); err != nil {
		return fmt.Errorf("error trying to disconnecting session for cryptounit %s: %s", cryptoUnitID, err.Error())
	}
	keyProtectCryptoUnitAPI.logger.Debug(fmt.Sprintf("Zeroizing crypto unit %s...\n", cryptoUnitID))
	pathParamsMap := map[string]string{
		"crypto_unit_id": cryptoUnitID,
	}

	builder := core.NewRequestBuilder(core.POST)
	builder = builder.WithContext(ctx)
	_, err := builder.ResolveRequestURL(keyProtectCryptoUnitAPI.Service.Options.URL, `/api/v1/crypto_units/{crypto_unit_id}/zeroize`, pathParamsMap)
	if err != nil {
		err = core.SDKErrorf(err, "", "url-resolve-error", common.GetComponentInfo())
		return err
	}

	sdkHeaders := createHeadersfromContext(ctx, "zeroize-cryptounits", keyProtectCryptoUnitAPI.instanceID)
	sdkHeaders["Crypto-Unit-ID"] = cryptoUnitID
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}

	request, err := builder.Build()
	if err != nil {
		err = core.SDKErrorf(err, "", "build-error", common.GetComponentInfo())
		return err
	}

	var rawResponse *string
	response, err := keyProtectCryptoUnitAPI.Service.Request(request, &rawResponse)
	if err != nil {
		err = core.SDKErrorf(err, "", "request-error", common.GetComponentInfo())
		return err
	}
	if response.StatusCode < 200 && response.StatusCode > 299 {
		return core.SDKErrorf(err, "", "request-error", common.GetComponentInfo())
	}
	return nil
}

// Internal Functions

// getCryptoUserMetadata retrieves crypto user metadata from the Key Protect management API
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) getCryptoUserMetadataWithContext(ctx context.Context) (*CryptoUserMetadata, error) {
	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	_, err := builder.ResolveRequestURL(keyProtectCryptoUnitAPI.Service.Options.URL, `/api/v1/cryptouser/metadata`, nil)
	if err != nil {
		return nil, core.SDKErrorf(err, "", "url-resolve-error", common.GetComponentInfo())
	}

	sdkHeaders := common.GetSdkHeaders(DefaultServiceName, "v1", "GetCryptoUserMetadata")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Instance-ID", keyProtectCryptoUnitAPI.instanceID)

	request, err := builder.Build()
	if err != nil {
		return nil, core.SDKErrorf(err, "", "build-error", common.GetComponentInfo())
	}

	var rawResponse *string
	response, err := keyProtectCryptoUnitAPI.Service.Request(request, &rawResponse)
	if err != nil {
		return nil, core.SDKErrorf(err, "", "request-error", common.GetComponentInfo())
	}

	jsonBytesPtr, ok := response.Result.(*string)
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", response.Result)
	}
	// Parse the response
	var metadata CryptoUserMetadata

	err = json.Unmarshal([]byte(*jsonBytesPtr), &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal crypto user metadata: %w", err)
	}
	return &metadata, nil
}
