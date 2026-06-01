package dedicated

import "fmt"

// CryptoUnitAPIError represents an error from the API
type CryptoUnitAPIError struct {
	Code    uint32
	Message string
}

// Error implements the error interface
func (e *CryptoUnitAPIError) Error() string {
	return fmt.Sprintf("API error 0x%08X: %s", e.Code, e.Message)
}

// NewError creates a new APIError
func NewError(code uint32, message string) *CryptoUnitAPIError {
	return &CryptoUnitAPIError{
		Code:    code,
		Message: message,
	}
}

// IsAuthError checks if the error is an authentication error
func IsAuthError(err error) bool {
	if e, ok := err.(*CryptoUnitAPIError); ok {
		return e.Code >= 0xC2000300 && e.Code < 0xC2000400
	}
	return false
}

// IsConnectionError checks if the error is a connection error
func IsConnectionError(err error) bool {
	if e, ok := err.(*CryptoUnitAPIError); ok {
		return e.Code >= 0xC2000100 && e.Code < 0xC2000200
	}
	return false
}

// IsSessionError checks if the error is a session error
func IsSessionError(err error) bool {
	if e, ok := err.(*CryptoUnitAPIError); ok {
		return e.Code >= 0xC2000600 && e.Code < 0xC2000700
	}
	return false
}

// IsUserError checks if the error is a user management error
func IsUserError(err error) bool {
	if e, ok := err.(*CryptoUnitAPIError); ok {
		return e.Code >= 0xC2000C00 && e.Code < 0xC2000D00
	}
	return false
}

// TranslateErrorCode converts a numeric error code to a human-readable message
// This is useful for debugging and logging when you have a raw error code
func TranslateErrorCode(code uint32) string {
	// Convert to hex for display
	hexCode := fmt.Sprintf("0x%08X", code)

	// Check if it's a known error code
	msg := getErrorMessage(code)
	if msg != "" {
		return fmt.Sprintf("%s: %s", hexCode, msg)
	}

	// Unknown error code
	return fmt.Sprintf("%s: unknown error code", hexCode)
}

// getErrorMessage returns the error message for a given error code
func getErrorMessage(code uint32) string {
	switch code {
	// Success
	case 0x00000000:
		return "success"

	// Crypto Basic Errors
	case 0xC7000001:
		return "invalid argument such as a NULL pointer"
	case 0xC7000002:
		return "buffer too small"
	case 0xC7000003:
		return "API version incompatible"
	case 0xC7000004:
		return "operation not supported"
	case 0xC7000005:
		return "device unexpected error"
	case 0xC7000006:
		return "client unexpected error"
	case 0xC7000007:
		return "device crypto error"
	case 0xC7000008:
		return "client crypto error"
	case 0xC7000009:
		return "library not initialized"
	case 0xC700000A:
		return "value out of range"
	case 0xC7000010:
		return "unable to allocate memory"

	// Crypto Connection Errors
	case 0xC7000100:
		return "communication problem"
	case 0xC7000101:
		return "operation timed out"
	case 0xC7000102:
		return "connection refused"
	case 0xC7000103:
		return "connection closed"

	// Crypto Authentication Errors
	case 0xC7000300:
		return "authentication failed"
	case 0xC7000301:
		return "user authenticated twice"
	case 0xC7000302:
		return "insufficient permissions"
	case 0xC7000303:
		return "lockout prevented"
	case 0xC7000306:
		return "auth key missing"
	case 0xC7000307:
		return "cert chain verification failed"

	// Crypto Session Errors
	case 0xC7000600:
		return "session invalid"
	case 0xC7000601:
		return "session wrong state"
	case 0xC7000602:
		return "session not connected"

	// Crypto User Errors
	case 0xC7000C00:
		return "user unknown"
	case 0xC7000C01:
		return "user exists"
	case 0xC7000C02:
		return "username invalid"
	case 0xC7000C03:
		return "user limit reached"
	case 0xC7000C05:
		return "invalid credentials"

	// CMS Errors (0xB1B39xxx range)
	case 0xB1B39C40:
		return "error with request parameters"
	case 0xB1B39C41:
		return "error with the request body"
	case 0xB1B39C42:
		return "invalid Content-Length"
	case 0xB1B39C45:
		return "error with request body"
	case 0xB1B39C46:
		return "error with request headers"
	case 0xB1B39CA4:
		return "user is not authorized to perform this operation"
	case 0xB1B39DD0:
		return "not found"
	case 0xB1B39DD1:
		return "crypto unit not found"
	case 0xB1B39FC4:
		return "cannot perform action due to a conflict"
	case 0xB1B39FC5:
		return "cannot perform action, CU must be claimed first"
	case 0xB1B3C350:
		return "an internal error has occurred, please try again later"

	// File/Key Errors (0xB906xxxx range)
	case 0xB9061003:
		return "unable to open keyfile"
	case 0xB9061004:
		return "unknown type of keyfile"
	case 0xB9061005:
		return "error reading keyfile"
	case 0xB9061006:
		return "error writing keyfile"
	case 0xB9061007:
		return "wrong keyfile format in .tok file"
	case 0xB9061008:
		return "wrong keyfile format in .key file"
	case 0xB9061009:
		return "wrong file name"
	case 0xB906100E:
		return "can't decrypt keyfile"

	// HTTP Errors (0xB9032xxx range)
	case 0xB9032001:
		return "couldn't connect to server"
	case 0xB9032002:
		return "result could not be parsed"
	case 0xB9032003:
		return "host name could not be resolved"
	case 0xB9032006:
		return "handshake error"
	case 0xB9032007:
		return "TLS handshake CA file could not be loaded"

	// IAM Token Error
	case 0x00000008:
		return "unable to get IAM token, please login or refresh session"

	default:
		return ""
	}
}
