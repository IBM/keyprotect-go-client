//go:build !disable_purego

package dedicated

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/ebitengine/purego"
)

var (
	libHandle uintptr
	initOnce  sync.Once
	initError error

	// Function pointers loaded from shared library
	// These match the //export functions in internal/bridge/exports.go
	createSessionFunc      func(endpoint *byte, port int32, instanceID *byte, cryptoUnitID *byte, username *byte, keyfile *byte, passphrase *byte, iamToken *byte) uintptr
	closeSessionFunc       func(sessionID uintptr) int32
	setTokenGetterFunc     func(sessionID uintptr, token *byte) int32
	getAuthStateFunc       func(sessionID uintptr, authState *int32) int32
	listUsersFunc          func(sessionID uintptr, result **byte) int32
	addUserFunc            func(sessionID uintptr, username *byte, userType *byte, credential *byte, credHash *byte, attributes *byte, headers *byte, result **byte) int32
	deleteUserFunc         func(sessionID uintptr, username *byte) int32
	generateRSAKeyFunc     func(instanceID *byte, keySpec *byte, keySizeBits uint32, owner *byte, passphrase *byte, result **byte) int32
	generateECDSAKeyFunc   func(instanceID *byte, keySpec *byte, curve *byte, owner *byte, passphrase *byte, result **byte) int32
	listMBKKeysFunc        func(sessionID uintptr, result **byte) int32
	generateMBKFunc        func(sessionID uintptr, keyspec *byte, keytype *byte, keylen int32, n uint8, k uint8, keyname *byte, headers *byte, result **byte) int32
	importMBKFunc          func(sessionID uintptr, keyspec *byte, slotNo int32, headers *byte, result **byte) int32
	changeUserPasswordFunc func(sessionID uintptr, username *byte, oldPassword *byte, newPassword *byte) int32
	getCryptoUnitIDFunc    func(sessionID uintptr, result **byte) int32
	freeStringFunc         func(str *byte)
	getLastErrorFunc       func(sessionID uintptr, result **byte) int32

	// Single authenticator for the client - used to get/refresh IAM tokens
	clientAuthenticator core.Authenticator

	// Session token map - stores session ID to allow token refresh
	sessionTokens = make(map[uintptr]string)
)

// initLibrary performs one-time library initialization with lazy loading.
// It checks platform support, loads the shared library, and registers function symbols.
// This function is thread-safe and will only execute once, even if called multiple times.
func initLibrary() error {
	initOnce.Do(func() {
		// Check platform support first
		var libName string
		switch runtime.GOOS {
		case "linux":
			libName = "ibmkmscrypto.so.1.0.0"
		case "windows":
			libName = "ibmkmscrypto.dll"
		case "darwin":
			libName = "ibmkmscrypto.1.0.0.dylib"
		default:
			initError = fmt.Errorf("unsupported platform: %s (supported: linux, windows, darwin)", runtime.GOOS)
			return
		}

		// Load library
		libPath := getLibraryPath(libName)
		ensurePreload(libPath)

		var err error
		libHandle, err = purego.Dlopen(libPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			initError = fmt.Errorf("failed to load library %s: %w\nTry setting KEYPROTECT_LIB_PATH environment variable", libPath, err)
			return
		}

		// Load function symbols
		// These must match the //export function names in internal/bridge/exports.go
		purego.RegisterLibFunc(&createSessionFunc, libHandle, "CreateSessionC")
		purego.RegisterLibFunc(&closeSessionFunc, libHandle, "CloseSessionC")
		purego.RegisterLibFunc(&setTokenGetterFunc, libHandle, "SetTokenGetterC")
		purego.RegisterLibFunc(&getAuthStateFunc, libHandle, "GetAuthStateC")
		purego.RegisterLibFunc(&listUsersFunc, libHandle, "ListUsersC")
		purego.RegisterLibFunc(&addUserFunc, libHandle, "AddUserC")
		purego.RegisterLibFunc(&deleteUserFunc, libHandle, "DeleteUserC")
		purego.RegisterLibFunc(&generateRSAKeyFunc, libHandle, "GenerateRSAKeyC")
		purego.RegisterLibFunc(&generateECDSAKeyFunc, libHandle, "GenerateECDSAKeyC")
		purego.RegisterLibFunc(&listMBKKeysFunc, libHandle, "ListMBKKeysC")
		purego.RegisterLibFunc(&generateMBKFunc, libHandle, "GenerateMBKC")
		purego.RegisterLibFunc(&importMBKFunc, libHandle, "ImportMBKC")
		purego.RegisterLibFunc(&changeUserPasswordFunc, libHandle, "ChangeUserPasswordC")
		purego.RegisterLibFunc(&getCryptoUnitIDFunc, libHandle, "GetCryptoUnitIDC")
		purego.RegisterLibFunc(&freeStringFunc, libHandle, "FreeStringC")
		purego.RegisterLibFunc(&getLastErrorFunc, libHandle, "GetLastErrorC")
	})

	return initError
}

// getLibraryPath searches for the shared library in multiple locations
func getLibraryPath(libName string) string {
	// 1. Try environment variable first (highest priority)
	if path := os.Getenv("KEYPROTECT_LIB_PATH"); path != "" {
		fullPath := filepath.Join(path, libName)
		// #nosec G703 - This is intentional: users can specify custom library paths via environment variable
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}

	// 2. Try embedded library in module source (for go get)
	// This searches relative to the source file location
	_, sourceFile, _, ok := runtime.Caller(0)
	if ok {
		sourceDir := filepath.Dir(sourceFile)
		platform := runtime.GOOS + "-" + runtime.GOARCH

		embeddedPaths := []string{
			// In internal/lib/{platform}/ relative to this source file
			filepath.Join(sourceDir, "internal", "lib", platform, libName),
			// Fallback: in lib/{platform}/ relative to this source file
			filepath.Join(sourceDir, "lib", platform, libName),
		}

		for _, path := range embeddedPaths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	// 3. Try relative to executable
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)

		searchPaths := []string{
			// Next to executable
			filepath.Join(exeDir, libName),
			// In lib subdirectory
			filepath.Join(exeDir, "lib", libName),
			// In platform-specific lib subdirectory
			filepath.Join(exeDir, "lib", runtime.GOOS+"-"+runtime.GOARCH, libName),
			// One level up (for development)
			filepath.Join(exeDir, "..", "lib", libName),
			filepath.Join(exeDir, "..", "lib", runtime.GOOS+"-"+runtime.GOARCH, libName),
		}

		for _, path := range searchPaths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	// 3. Try current working directory
	if cwd, err := os.Getwd(); err == nil {
		cwdPaths := []string{
			filepath.Join(cwd, libName),
			filepath.Join(cwd, "lib", libName),
			filepath.Join(cwd, "lib", runtime.GOOS+"-"+runtime.GOARCH, libName),
		}

		for _, path := range cwdPaths {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	// 4. Fallback to system library path (LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, etc.)
	return libName
}

// Helper functions for string conversion

// cString converts a Go string to a null-terminated byte slice
func cString(s string) *byte {
	if s == "" {
		return nil
	}
	b := append([]byte(s), 0)
	return &b[0]
}

// goString converts a C string (null-terminated byte pointer) to a Go string
func goString(cstr *byte) string {
	if cstr == nil {
		return ""
	}

	var length int
	for *(*byte)(unsafe.Add(unsafe.Pointer(cstr), length)) != 0 {
		length++
	}

	return string(unsafe.Slice(cstr, length))
}

// getIAMToken retrieves a fresh IAM token using the client authenticator
// The authenticator handles token caching and refresh automatically
func getIAMToken() (string, error) {
	if clientAuthenticator == nil {
		return "", fmt.Errorf("no authenticator configured")
	}

	// Create a dummy request to get the token
	// The authenticator will add the Authorization header with a fresh token
	builder := core.NewRequestBuilder(core.GET)
	_, err := builder.ConstructHTTPURL("https://iam.cloud.ibm.com/identity/token", nil, nil)
	if err != nil {
		return "", fmt.Errorf("failed to construct URL: %w", err)
	}

	httpReq, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}

	// Authenticate the request - this will fetch/refresh the token as needed
	err = clientAuthenticator.Authenticate(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}

	// Extract the token from the Authorization header
	authHeader := httpReq.Header.Get("Authorization")
	return authHeader, nil
}

// refreshSessionToken gets a fresh IAM token and updates it in the C library
func refreshSessionToken(sessionID uintptr) error {
	token, err := getIAMToken()
	if err != nil {
		return fmt.Errorf("failed to get IAM token: %w", err)
	}

	// Update the token in the C library
	result := setTokenGetterFunc(sessionID, cString(token))
	if result != 0 {
		return fmt.Errorf("failed to set token in C library")
	}

	sessionTokens[sessionID] = token
	return nil
}

// getLastErrorMessage retrieves the last error message from the C library and translates the error code
func getLastErrorMessage(sessionID uintptr, errorCode uint32) string {
	// Try to get detailed error from C library
	if errStr, err := callGetLastError(sessionID); err == nil && errStr != "" {
		return errStr
	}

	// Fallback to error code translation
	return TranslateErrorCode(errorCode)
}

// callCreateSession wraps the C function call to create a session
func callCreateSession(endpoint, instanceID, cryptoUnitID, username, keyfile, passphrase string, port int, authenticator core.Authenticator) (uintptr, error) {
	// Store the authenticator - it will be used for all token requests
	clientAuthenticator = authenticator

	// Get initial IAM token
	token, err := getIAMToken()
	if err != nil {
		return 0, fmt.Errorf("failed to get IAM token: %w", err)
	}

	// Validate port is within int32 range
	if port < 0 || port > 2147483647 {
		return 0, fmt.Errorf("port %d is out of valid range", port)
	}
	// Create session with initial token
	sessionID := createSessionFunc(
		cString(endpoint),
		int32(port),
		cString(instanceID),
		cString(cryptoUnitID),
		cString(username),
		cString(keyfile),
		cString(passphrase),
		cString(token),
	)

	if sessionID == 0 {
		return 0, NewError(0xC7000005, "failed to create session for cryptounit "+cryptoUnitID)
	}

	// Store the session token and set up refresh
	sessionTokens[sessionID] = token
	err = refreshSessionToken(sessionID)
	if err != nil {
		closeSessionFunc(sessionID)
		return 0, fmt.Errorf("failed to set token getter: %s", cryptoUnitID)
	}

	return sessionID, nil
}

// callCloseSession wraps the C function call to close the session
func callCloseSession(sessionID uintptr) error {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return fmt.Errorf("library initialization failed: %w", err)
	}

	result := closeSessionFunc(sessionID)
	if result != 0 {
		// Validate result is non-negative before conversion
		if result < 0 {
			return fmt.Errorf("failed to close session: invalid result code %d", result)
		}
		errMsg := getLastErrorMessage(sessionID, uint32(result))
		return fmt.Errorf("failed to close session: %s", errMsg)
	}
	return nil
}

// callGetAuthState wraps the C function call to get the auth state of the cryptounit session
func callGetAuthState(sessionID uintptr) (int32, error) {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return 0, fmt.Errorf("library initialization failed: %w", err)
	}

	var authState int32
	result := getAuthStateFunc(sessionID, &authState)
	if result != 0 {
		// Validate result is non-negative before conversion
		if result < 0 {
			return 0, fmt.Errorf("failed to get auth state: invalid result code %d", result)
		}
		// #nosec G115 - Result is validated to be non-negative before conversion
		errMsg := getLastErrorMessage(sessionID, uint32(result))
		return 0, fmt.Errorf("failed to get auth state: %s", errMsg)
	}
	return authState, nil
}

// callListUsers wraps the C function call to list users in the cryptounit
func callListUsers(sessionID uintptr) (string, error) {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return "", fmt.Errorf("library initialization failed: %w", err)
	}

	var resultPtr *byte
	status := listUsersFunc(sessionID, &resultPtr)
	if status != 0 {
		// Validate status is non-negative before conversion
		if status < 0 {
			return "", fmt.Errorf("failed to list users: invalid status code %d", status)
		}
		// #nosec G115 - Status is validated to be non-negative before conversion
		errMsg := getLastErrorMessage(sessionID, uint32(status))
		return "", fmt.Errorf("failed to list users: %s", errMsg)
	}

	defer freeStringFunc(resultPtr)
	return goString(resultPtr), nil
}

// callAddUser wraps the C function call
// attributes should be a semicolon-separated string of key=value pairs (e.g., "CXI_GROUP=SLOT_0042;KEY2=VALUE2")
func callAddUser(sessionID uintptr, username, userType, credential, credHash, attributes string, addtlHeaders map[string]string) error {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return fmt.Errorf("library initialization failed: %w", err)
	}

	headerStr := convertHeadersToString(addtlHeaders)
	var resultPtr *byte
	status := addUserFunc(
		sessionID,
		cString(username),
		cString(userType),
		cString(credential),
		cString(credHash),
		cString(attributes),
		cString(headerStr),
		&resultPtr,
	)

	defer freeStringFunc(resultPtr)
	result := goString(resultPtr)

	if status != 0 {
		// Result contains error message when status is non-zero
		return fmt.Errorf("failed to add user %s: %s", username, result)
	}

	return nil
}

// callDeleteUser wraps the C function call
func callDeleteUser(sessionID uintptr, username string) error {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return fmt.Errorf("library initialization failed: %w", err)
	}

	result := deleteUserFunc(sessionID, cString(username))
	if result != 0 {
		// Validate result is non-negative before conversion
		if result < 0 {
			return fmt.Errorf("failed to delete user: invalid result code %d", result)
		}
		// #nosec G115 - Result is validated to be non-negative before conversion
		errMsg := getLastErrorMessage(sessionID, uint32(result))
		return fmt.Errorf("failed to delete user: %s", errMsg)
	}
	return nil
}

// callGenerateRSAKeyStatic generates an RSA key using instance ID directly (no session required)
// This is a local operation that doesn't communicate with the HSM
func callGenerateRSAKeyStatic(instanceID, keySpec string, keySizeBits uint32, owner, passphrase string) error {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return fmt.Errorf("library initialization failed: %w", err)
	}

	var resultPtr *byte
	status := generateRSAKeyFunc(
		cString(instanceID),
		cString(keySpec),
		keySizeBits,
		cString(owner),
		cString(passphrase),
		&resultPtr,
	)

	defer freeStringFunc(resultPtr)
	result := goString(resultPtr)

	if status != 0 {
		// Result contains error message when status is non-zero
		return fmt.Errorf("failed to generate RSA key: %s", result)
	}

	return nil
}

// callListMasterKeys wraps the C function call to list Master Keys
func callListMasterKeys(sessionID uintptr) (string, error) {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return "", fmt.Errorf("library initialization failed: %w", err)
	}

	var resultPtr *byte
	status := listMBKKeysFunc(sessionID, &resultPtr)
	if status != 0 {
		// Validate status is non-negative before conversion
		if status < 0 {
			return "", fmt.Errorf("failed to list MBK keys: invalid status code %d", status)
		}
		// #nosec G115 - Status is validated to be non-negative before conversion
		errMsg := getLastErrorMessage(sessionID, uint32(status))
		return "", fmt.Errorf("failed to list MBK keys: %s", errMsg)
	}

	defer freeStringFunc(resultPtr)
	return goString(resultPtr), nil
}

// callGenerateMBK wraps the C function call to generate Master key
func callGenerateMBK(sessionID uintptr, keyspec, keytype string, keylen int, n, k uint8, keyname string, addtlHeaders map[string]string) error {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return fmt.Errorf("library initialization failed: %w", err)
	}

	headerStr := convertHeadersToString(addtlHeaders)

	// Validate keylen is within int32 range
	if keylen < 0 || keylen > 2147483647 {
		return fmt.Errorf("key length %d is out of valid range", keylen)
	}
	var resultPtr *byte
	status := generateMBKFunc(
		sessionID,
		cString(keyspec),
		cString(keytype),
		int32(keylen),
		n,
		k,
		cString(keyname),
		cString(headerStr),
		&resultPtr,
	)

	defer freeStringFunc(resultPtr)
	result := goString(resultPtr)

	if status != 0 {
		// Result contains error message when status is non-zero
		return fmt.Errorf("failed to generate MBK: %s", result)
	}

	return nil
}

// callImportMasterKey wraps the C function call to import Master key
func callImportMasterKey(sessionID uintptr, keyspec string, slotNo int, addtlHeaders map[string]string) error {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return fmt.Errorf("library initialization failed: %w", err)
	}

	// Convert headers map to semicolon-separated string
	headerStr := convertHeadersToString(addtlHeaders)

	// Validate slotNo is within int32 range
	if slotNo < 0 || slotNo > 2147483647 {
		return fmt.Errorf("slot number %d is out of valid range", slotNo)
	}
	var resultPtr *byte
	status := importMBKFunc(
		sessionID,
		cString(keyspec),
		int32(slotNo),
		cString(headerStr),
		&resultPtr,
	)

	defer freeStringFunc(resultPtr)
	result := goString(resultPtr)

	if status != 0 {
		// Result contains error message when status is non-zero
		return fmt.Errorf("failed to import MBK: %s", result)
	}

	return nil
}

// callGetCryptoUnitID wraps the C function call to obtain the crypto unit ID
func callGetCryptoUnitID(sessionID uintptr) (string, error) {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return "", fmt.Errorf("library initialization failed: %w", err)
	}

	var resultPtr *byte
	status := getCryptoUnitIDFunc(sessionID, &resultPtr)
	if status != 0 {
		// Validate status is non-negative before conversion
		if status < 0 {
			return "", fmt.Errorf("failed to get crypto unit ID: invalid status code %d", status)
		}
		// #nosec G115 - Status is validated to be non-negative before conversion
		errMsg := getLastErrorMessage(sessionID, uint32(status))
		return "", fmt.Errorf("failed to get crypto unit ID: %s", errMsg)
	}

	defer freeStringFunc(resultPtr)
	return goString(resultPtr), nil
}

// callGetLastError wraps the C function call to get the last error message
func callGetLastError(sessionID uintptr) (string, error) {
	// Initialize library if not already done
	if err := initLibrary(); err != nil {
		return "", fmt.Errorf("library initialization failed: %w", err)
	}

	var resultPtr *byte
	status := getLastErrorFunc(sessionID, &resultPtr)
	if status != 0 {
		return "", fmt.Errorf("failed to get last error")
	}

	defer freeStringFunc(resultPtr)
	return goString(resultPtr), nil
}

// convertHeadersToString converts map[string]string to a string of "key=value" pairs separated by a rune,
func convertHeadersToString(addtlHeaders map[string]string) string {
	var headerStr string
	if len(addtlHeaders) > 0 {
		var parts []string
		for k, v := range addtlHeaders {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
		headerStr = strings.Join(parts, "%")
	}
	return headerStr
}

// wrapError wraps an error while preserving CryptoUnitAPIError type
func wrapError(err error, context string) error {
	if apiErr, ok := err.(*CryptoUnitAPIError); ok {
		// Preserve the CryptoUnitAPIError by returning it directly
		// or wrapping it in a way that errors.As can unwrap
		return apiErr
	}
	return fmt.Errorf("%s: %w", context, err)
}

func ensurePreload(libPath string) {
	// Only do this on Linux
	if runtime.GOOS != "linux" {
		return
	}

	// Avoid infinite recursion
	if os.Getenv("KP_PRELOADED") == "1" {
		return
	}

	// If already preloaded, skip
	if strings.Contains(os.Getenv("LD_PRELOAD"), libPath) {
		return
	}

	// Build new environment
	env := os.Environ()
	env = append(
		env,
		"LD_PRELOAD="+libPath,
		"KP_PRELOADED=1",
	)

	// Re-exec current process
	// #nosec G204,G702 - This is intentional: re-executing the current process with modified environment
	err := syscall.Exec(os.Args[0], os.Args, env)
	if err != nil {
		panic(fmt.Sprintf("failed to exec with LD_PRELOAD: %v", err))
	}
}

// Made with Bob
