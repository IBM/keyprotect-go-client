package dedicated

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/keyprotect-go-client/dedicated/common"
)

// detachedCtx wraps a parent context but is immune to its cancellation.
// It inherits all Values (auth tokens, request headers, etc.) from the
// parent, but Done() always returns nil, Err() always returns nil, and
// Deadline() always reports no deadline.  As a result, net/http will
// never abort an in-flight request because the parent was canceled.
type detachedCtx struct{ context.Context }

func (detachedCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (detachedCtx) Done() <-chan struct{}       { return nil }
func (detachedCtx) Err() error                  { return nil }

// detachContext returns a context that carries parent's values but cannot
// be canceled or timed out by the parent. If parent is already a
// detachedCtx it is returned as-is to avoid unnecessary wrapping.
func detachContext(parent context.Context) context.Context {
	if _, ok := parent.(detachedCtx); ok {
		return parent
	}
	return detachedCtx{parent}
}

func getHeaders(ctx context.Context) map[string]string {
	if headers, ok := ctx.Value(headersKey).(map[string]string); ok {
		return headers
	}
	return nil
}

// Store headers
func withHeaders(ctx context.Context, headers map[string]string) context.Context {
	return context.WithValue(ctx, headersKey, headers)
}

// Create SDK headers with context, action, and instance ID
func createHeadersfromContext(ctx context.Context, action, instanceID string) map[string]string {
	ctxHeaders := getHeaders(ctx)
	if ctxHeaders == nil {
		ctxHeaders = common.GetSdkHeaders(DefaultServiceName, common.Version, action)
	} else {
		ctxHeaders["X-IBMCloud-SDK-Analytics"] = common.GetSdkAnalyticsHeader(DefaultServiceName, common.Version, action)
	}
	ctxHeaders[common.HeaderNamexRequestID] = common.GetNewUUID()
	if xID, ok := common.GetXCorrelationIDHeader(ctxHeaders); ok && xID != "" {
		ctxHeaders[common.HeaderNamexCorrelationID] = xID
		ctxHeaders["Correlation-Id"] = xID
	} else {
		crreID := common.GetNewUUID()
		ctxHeaders[common.HeaderNamexCorrelationID] = crreID
		ctxHeaders["Correlation-Id"] = crreID
	}
	ctxHeaders["Instance-ID"] = instanceID
	ctxHeaders["Bluemix-Instance"] = instanceID
	return ctxHeaders
}

// callGenerateSignatureKeyStatic calls the bridge layer to generate a signature key
// This is a local operation that doesn't require a session
func callGenerateSignatureKeyStatic(instanceID, filePath string, keySizeBits uint32, passphrase string, owner string) (string, error) {
	// Use the static RSA key generation function from purego_link.go
	// This is a local operation that doesn't communicate with the HSM
	err := callGenerateRSAKeyStatic(instanceID, filePath, keySizeBits, owner, passphrase)
	if err != nil {
		return "", err
	}
	return "RSA key generated successfully", nil
}

// parseServiceURL extracts instance-id and region from a Key Protect service URL
// Expected format: https://<instance-id>.api.<region>.kms.appdomain.cloud
// or https://<instance-id>.api.<?private>.<env>.<region>.kms.<?test>.appdomain.cloud
//
// keys: instance_id,private,is_private, is_test, region
func parseServiceURL(url string) (result map[string]string, err error) {
	if url == "" {
		return nil, errors.New("url for cryptounit cannot be empty")
	}
	// Remove protocol if present
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Remove trailing slash if present
	url = strings.TrimSuffix(url, "/")

	// Pattern: <instance-id>.api.<region>.kms[.test].appdomain.cloud
	// Region can contain dots (e.g., dev-dn-st.eu-gb)
	pattern := `^(?P<instance_id>[^.]+)\.api\.(?P<is_private>private\.)?(?:(?P<env>[^.]+)\.)?(?P<region>[^.]+)\.kms\.(?:(?P<is_test>test)\.)?appdomain\.cloud$`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(url)
	if len(matches) == 0 {
		err = fmt.Errorf("cannot find any matches to the url provided: %s", url)
		return nil, err
	}
	names := re.SubexpNames()
	if len(names) == 0 {
		return nil, fmt.Errorf("cannot parse the service url given: %s", url)
	}
	result = make(map[string]string)

	for i, name := range names {
		if i != 0 && name != "" {
			result[name] = matches[i]
		}
	}

	return
}

// parseSignatureKeyFile parses a signature key file and extracts MOD and PEXP values
func parseSignatureKeyFile(filePath string) (modulusHex, exponentHex string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open signature key file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse key=value pairs
		if strings.HasPrefix(line, "MOD=") {
			modulusHex = strings.TrimPrefix(line, "MOD=")
		} else if strings.HasPrefix(line, "PEXP=") {
			exponentHex = strings.TrimPrefix(line, "PEXP=")
		}

		// Stop once we have both values
		if modulusHex != "" && exponentHex != "" {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("error reading signature key file: %w", err)
	}

	if modulusHex == "" {
		return "", "", fmt.Errorf("MOD not found in signature key file")
	}
	if exponentHex == "" {
		return "", "", fmt.Errorf("PEXP not found in signature key file")
	}

	return modulusHex, exponentHex, nil
}

// convertRSAKeyToPEM converts RSA modulus and exponent (in hex format) to PEM-encoded public key
func convertRSAKeyToPKCS1(modulusHex, exponentHex string) ([]byte, error) {
	// Convert MOD string into big.Int
	modulus := new(big.Int)
	modulus.SetString(modulusHex, 16)

	// Convert PEXP from hex to decimal
	exponentDec, err := strconv.ParseInt(exponentHex, 16, 32)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to parse exponent: %w", err)
	}

	// Create RSA public key
	pubKey := rsa.PublicKey{
		N: modulus,
		E: int(exponentDec),
	}

	// MarshalPKCS1PublicKey converts an RSA public key to PKCS #1, ASN.1 DER form
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&pubKey)
	return pubKeyBytes, nil
}

func convertBytesToClaimBody(pubKeyBytes []byte) (CryptoUnitClaimBody, error) {
	// Decode the PEM block
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	var pubKeyString bytes.Buffer
	err := pem.Encode(&pubKeyString, publicKeyPEM)
	if err != nil {
		return CryptoUnitClaimBody{}, fmt.Errorf("failed to encode PEM: %w", err)
	}

	// Normalize newlines
	re := regexp.MustCompile(`\r?\n`)
	newline := re.ReplaceAllString(pubKeyString.String(), "\n")

	return CryptoUnitClaimBody{
		PublicKey: newline,
	}, nil
}

// convertPEMToRSAFormat converts a PEM-encoded RSA public key to HSM format (MOD/PEXP)
func convertPEMToRSAFormat(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKCS1 public key first

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		// If PKCS1 fails, try PKIX format
		pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse public key: %w", err)
		}
		var ok bool
		publicKey, ok = pubKeyInterface.(*rsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("public key is not RSA")
		}
	}

	// Format as HSM expects: MOD and PEXP in hexadecimal
	output := "# RSA key\n"
	output += fmt.Sprintf("MOD=%x\n", publicKey.N)
	output += fmt.Sprintf("PEXP=%06x\n", publicKey.E)

	return output, nil
}

// sha256Hash computes the SHA-256 hash of a string
func sha256Hash(data string) []byte {
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// parseMasterKeyListOutput parses the table format output from ListMasterKeys
// Expected format:
// slot name     len algo type   k  generation date      key check value
// ---------------------------------------------------------------------------------------
// 3    AUTO-GEN 32  AES  SHARE  1  2026/04/27 19:21:50  fdca29d11b2fff3b:caaf20ff34786279
func parseMasterKeyListOutput(output string) ([]MasterKeyInfo, error) {
	var keys []MasterKeyInfo

	// Split by newlines
	lines := strings.Split(output, "\n")

	// Skip header and separator lines, process data lines
	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, header line (index 0), and separator line (index 1)
		if line == "" || i == 0 || strings.HasPrefix(line, "---") {
			continue
		}

		// Split by whitespace, but we need to handle the generation date which has spaces
		// Format: slot name len algo type k date(YYYY/MM/DD HH:MM:SS) key_check_value
		fields := strings.Fields(line)

		if len(fields) < 8 {
			// Not enough fields, skip this line
			continue
		}

		// Parse fields:
		// 0: slot, 1: name, 2: len, 3: algo, 4: type, 5: k, 6: date, 7: time, 8: key_check_value
		key := MasterKeyInfo{
			Slot: fields[0],
			Name: fields[1],
			Len:  fields[2],
			Algo: fields[3],
			Type: fields[4],
			K:    fields[5],
		}

		// Combine date and time fields
		if len(fields) >= 8 {
			key.GenerationDate = fields[6] + " " + fields[7]
		}

		// Key check value is the last field
		if len(fields) >= 9 {
			key.KeyCheckValue = fields[8]
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) generateMasterKeyHelper(ctx context.Context, cryptoUnitID string, request *MasterKeyRequest) (string, error) {
	sdkHeaders := createHeadersfromContext(ctx, "generate-master-key", keyProtectCryptoUnitAPI.instanceID)
	if request == nil {
		return "", fmt.Errorf("request cannot be nil")
	}

	// Validate required parameters
	if request.KeySpec == "" {
		return "", fmt.Errorf("KeySpec is required")
	}
	if request.KeyType == "" {
		return "", fmt.Errorf("KeyType is required")
	}
	if request.KeyLength <= 0 {
		return "", fmt.Errorf("KeyLength must be positive")
	}
	if request.N == 0 || request.K == 0 {
		return "", fmt.Errorf("n and k threshold parameters are required")
	}
	if request.K > request.N {
		return "", fmt.Errorf("k (threshold: %d) cannot be greater than n (total parts: %d)", request.K, request.N)
	}
	if request.KeyName == "" {
		return "", fmt.Errorf("KeyName is required")
	}

	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return "", err
	}

	err = callGenerateMBK(
		sessionID,
		request.KeySpec,
		request.KeyType,
		request.KeyLength,
		request.N,
		request.K,
		request.KeyName,
		sdkHeaders,
	)
	if err != nil {
		return "", wrapError(err, fmt.Sprintf("failed to generate MasterKey from crypto unit %s", cryptoUnitID))
	}

	return "MasterKey generated successfully", nil
}

func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) createSessions(ctx context.Context, cryptounits CryptoUnits, keypath string) (func(), error) {
	// Detach from the caller's cancellation signal. This operation touches
	// durable HSM state and must not be interrupted mid-flight; values
	// (auth tokens, headers) are still inherited from the parent context.
	ctx = detachContext(ctx)

	for _, v := range cryptounits.CryptoUnits {
		cryptoUnitID := v.ID
		// Connect to the first crypto unit

		loginSpec := LoginSpec{
			KeyFile:      keypath,
			CryptoUnitID: cryptoUnitID,
			Port:         443,
			Username:     "ADMIN",
		}
		err := keyProtectCryptoUnitAPI.CreateCryptoUnitSession(
			&loginSpec,
		)
		if err != nil {
			return func() {}, fmt.Errorf("failed to establish a session to cryptounit %s: %v", cryptoUnitID, err)
		} else {
			keyProtectCryptoUnitAPI.logger.Info(fmt.Sprintf("Connected to cryptounit %s\n", cryptoUnitID))
		}
	}
	return func() {
		keyProtectCryptoUnitAPI.sessions.disconnectAll()
	}, nil
}

// configureKPCryptoUnitLogger configures the logger for the KeyProtectCryptoUnitAPI
func configureKPCryptoUnitLogger() core.Logger {
	var coreLogLevel core.LogLevel
	kpLogLevel := strings.ToUpper(os.Getenv("KP_LOG"))
	if kpLogLevel == "" {
		coreLogLevel = core.LevelNone
	} else {
		kpLogLevel := strings.ToUpper(kpLogLevel)
		// Map Terraform log levels to IBM SDK core log levels
		switch kpLogLevel {
		case "TRACE":
			// TRACE is the most verbose, map to Debug in IBM SDK
			coreLogLevel = core.LevelDebug
		case "DEBUG":
			coreLogLevel = core.LevelDebug
		case "INFO":
			coreLogLevel = core.LevelInfo
		case "WARN":
			coreLogLevel = core.LevelWarn
		case "ERROR":
			coreLogLevel = core.LevelError
		default:
			// If TF_LOG is set to any other value (e.g., "1", "true"), default to Debug
			coreLogLevel = core.LevelDebug
		}
	}

	logDestination := log.Writer()
	outLogger := log.New(logDestination, fmt.Sprintf("[%s] ", DefaultServiceName), log.LstdFlags)
	errLogger := log.New(os.Stderr, fmt.Sprintf("[%s] ", DefaultServiceName), log.LstdFlags)

	return core.NewLogger(coreLogLevel, outLogger, errLogger)
}

// ---------------------------------------------------------------------------
// InitStep — resume-point enumeration for InitializeCryptoUnits
// ---------------------------------------------------------------------------

// InitStep identifies each resumable stage of the initialization pipeline.
// The values are intentionally monotonically increasing so that a simple
// integer comparison determines whether a stage needs to run.
type InitStep int

const (
	StepListUnits      InitStep = 1 // ListCryptoUnitsWithContext → determines per-unit resume point
	StepGenerateSKR    InitStep = 2 // generate the admin signature key (local)
	StepClaimUnits     InitStep = 3 // ClaimCryptoUnitWithContext → state: claimed
	StepCreateSessions InitStep = 4 // createSessions (HSM login)
	StepAddKMSUser     InitStep = 5 // AddKMSUser → state: kms-authorized
	StepGenerateMBK    InitStep = 6 // GenerateMasterKeyWithContext (local-to-one-unit)
	StepImportMBK      InitStep = 7 // ImportMasterKeyToCryptoUnits → state: initialized
)

// stateToStep maps a CryptoUnitState to the earliest InitStep that still
// needs to execute for that unit.  It is the authoritative translation
// between the live HSM state and the initialization pipeline.
//
//	available / reserved  → need to Claim                         (Step 3)
//	claimed               → need Sessions + AddKMSUser + MBK      (Step 4)
//	kms-authorized        → need Sessions (ephemeral) + ImportMBK (Step 4)
//	initialized /
//	kms-initialized       → already done                          (Step 8, sentinel)
//
// NOTE: kms-authorized maps to StepCreateSessions (4), not StepImportMBK (7).
// HSM sessions are process-local and ephemeral — they are never persisted across
// process restarts.  Every code path that reaches Step 5 or beyond requires an
// active session, so sessions must always be (re-)opened, even when resuming from
// a state that has already passed the session-creation point.  The per-unit guards
// inside Steps 5, 6, and 7 handle skipping work that is already reflected in the
// durable HSM state; Step 4 itself is always unconditional.
//
// Any unknown / unexpected state falls back to StepClaimUnits so we
// conservatively redo the minimum required work without skipping anything.
func stateToStep(state CryptoUnitState) InitStep {
	switch state {
	case CryptoUnitStateAvailable, CryptoUnitStateReserved:
		return StepClaimUnits
	case CryptoUnitStateClaimed, CryptoUnitStateKMSAuthorized:
		// Both states need an HSM session opened before further work can proceed.
		// The per-unit guards in Steps 5–7 ensure only the missing durable work runs.
		return StepCreateSessions
	case CryptoUnitStateInitialized, CryptoUnitStateKMSInitialized:
		return StepImportMBK + 1 // sentinel: nothing left to do
	default:
		return StepClaimUnits
	}
}

// cryptoUnitStartStep returns the next InitStep that needs to execute for a
// single CryptoUnit, based on its live state from ListCryptoUnitsWithContext.
// It is a thin wrapper around stateToStep kept here for testability.
func cryptoUnitStartStep(cu CryptoUnit) InitStep {
	return stateToStep(cu.State)
}

// instanceStartStep returns the earliest InitStep that must still run across
// the entire set of crypto units — i.e. the minimum per-unit start step.
// Passing the minimum ensures no unit is left behind.
func instanceStartStep(units []CryptoUnit) InitStep {
	min := StepImportMBK + 1 // sentinel: all done
	for _, cu := range units {
		if s := stateToStep(cu.State); s < min {
			min = s
		}
	}
	return min
}
