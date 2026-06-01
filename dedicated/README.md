# KeyProtect CryptoUnit Go SDK - API

This package provides a simplified, secure Go interface to KeyProtect SingleTenant CryptoUnits.

## Overview

This is the **public API** for the KeyProtect SingleTenant keyprotect-dedicated Go wrapper. The actual implementation is packaged separately as platform-specific prebuilt artifacts while maintaining ease of use.

> Current packaging contract: the public module remains source-only, while the build pipeline publishes standardized platform archives containing redistributed prebuilt Go archive artifacts and vendor libraries for future integration.

## Installation

### Simple Installation (Recommended)

The easiest way to use this package is via `go get`. The shared libraries are **automatically included** with the module:

```bash
# Install the package (includes embedded shared libraries)
go get github.com/IBM/keyprotect-go-client/dedicated

# Use in your project - NO CGO REQUIRED!
# The libraries are automatically found at runtime
```

**Key Benefits:**

- ✅ **No CGO required** - Pure Go builds for consumers
- ✅ **Fast builds** - Compiles in seconds, not minutes
- ✅ **Easy cross-compilation** - Standard Go tooling works
- ✅ **Automatic library loading** - No manual setup needed

### How It Works

The module includes precompiled shared libraries for all supported platforms in `internal/lib/`:

- `linux-amd64/libc2api.so.${VERSION}`
- `darwin-arm64/libc2api.${VERSION}.dylib`
- `windows-amd64/libc2api.dll`

At runtime, the package automatically finds and loads the correct library for your platform using [purego](https://github.com/ebitengine/purego).

### Advanced: Custom Library Location

If you need to use a custom library version, set the environment variable:

```bash
export KEYPROTECT_LIB_PATH=/path/to/custom/libs
```

## Quick Start

### Using the Go API

```go
package main

import (
    "os"
    "fmt"
    "log"

    "github.com/IBM/go-sdk-core/v5/core"
    keyprotect_dedicated "github.com/IBM/keyprotect-go-client/dedicated"
)

func main() {
  iamAPIKey, apiKeyFound := os.LookupEnv("IBMCLOUD_API_KEY")

 // Create client configuration
 config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
  URL:         "https://<instance_id>.api.st.<region>.kms.appdomain.cloud",
  Authenticator: &core.IamAuthenticator{
   ApiKey: iamAPIKey,
   URL:    "https://iam.cloud.ibm.com",
  },
 }

 // Create new client
 client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
 if err != nil {
  log.Fatalf("Failed to create client: %v", err)
 }
 defer disconnect ()

 // Initialize all cryptounits
 rootKeySpec, err := keyprotect_dedicated.NewSignatureKeyRequest(
  "signature.key",
  "",
  "ADMIN",
  false,
 )
 if err != nil {
  log.Fatalf("error creating signature key request: %s", err)
 }

 mbkSpec, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
  2,
  "IFHLSM",
  []string{
   "mbk-1.key#abcd12",
   "mbk-2.key#abcd12",
  },
  false,
 )
 if err != nil {
  log.Fatalf("error creating NewMasterKeyPartsSpec  request: %s", err)
 }

 err = client.InitializeCryptoUnits(context.Background(), rootKeySpec, mbkSpec, instanceID)
 if err != nil {
  log.Fatalf("Failed to initialize cryptounits: %v", err)
 }

 // Get crypto units
 fmt.Println("Listing crypto units...")
 units, _, err := client.ListCryptoUnits(defaultSettings)
 if err != nil {
  log.Fatalf("Failed to list crypto units: %v", err)
 }

 fmt.Printf("Found %d crypto units:\n", len(units.CryptoUnits))

 for k, v := range units.CryptoUnits {
  fmt.Printf("index %d crypto units %v:\n", k, v)
 }

 // To connect to the first crypto unit and not initialize
 cryptoUnitID := units.CryptoUnits[0].ID

 err = client.CreateCryptoUnitSession(
  Username: "<username>", // username
  KeyFile: "<>", // key file path
  CryptoUnitID: cryptoUnitID, // crypto unit ID
  Port: 443,          // port (0 = default)
 )
 if err != nil {
  log.Fatalf("Failed to connect to crypto unit: %v", err)
 }
```

## API Reference

### Methods (on KeyProtectCryptoUnitAPI)

#### Factory Functions (Constructors)

- NewSignatureKeyRequest(filepath, passphrase, owner string, exists bool) (*SignatureKeyRequest, error)
- NewMasterKeyPartsSpec(K int, keyName string, keysharefiles []string, exists bool) (*MasterKeyPartsSpec, error)
- NewKeyProtectCryptoUnitAPIOptions(url string) (*KeyProtectCryptoUnitAPIOptions, error)
- NewKeyProtectCryptoUnitAPI(options *KeyProtectCryptoUnitAPIOptions) (service*KeyProtectCryptoUnitAPI, disconnect func(), err error)
- NewKeyProtectCryptoUnitAPIUsingExternalConfig(options *KeyProtectCryptoUnitAPIOptions) (keyProtectCryptoUnitAPI*KeyProtectCryptoUnitAPI, disconnect func(), err error)

#### Configuration & Setup

- SetDefaultHeaders(headers http.Header) - Sets default HTTP headers
- GetServiceURL() string - Gets the service URL
- SetLogger(logger core.Logger) - Sets the logger
- GetLogger() core.Logger - Gets the logger

#### Session Management

- CreateCryptoUnitSession(loginSpec *LoginSpec) error - Creates a session with a crypto unit
- GetConnectedCryptoUnits() []string - Gets list of connected crypto units
- Disconnect(cryptoUnitID string) error - Disconnects from a specific crypto unit
- DisconnectAll() - Disconnects from all crypto units
- GetSessionInfo(cryptoUnitID string) (*SessionInfo, error) - Gets session information
- GetAuthState(cryptoUnitID string) (uint32, error) - Gets authentication state

#### Crypto Unit Operations

- ListCryptoUnits() (cryptounits CryptoUnits, response *core.DetailedResponse, err error) - Lists crypto units
- ListCryptoUnitsWithContext(ctx context.Context) (crytounits CryptoUnits, response *core.DetailedResponse, err error) - Lists crypto units with context
- ClaimCryptoUnit(cryptoUnitID string, filepath string) error - Claims a crypto unit
- ClaimCryptoUnitWithContext(ctx context.Context, cryptoUnitID string, filePath string) error - Claims crypto unit with context
- ZeroizeCryptoUnit(cryptoUnitID string) error - Zeroizes a crypto unit
- ZeroizeCryptoUnitWithContext(ctx context.Context, cryptoUnitID string) error - Zeroizes crypto unit with context
- InitializeCryptoUnits(ctx context.Context, skr *SignatureKeyRequest, mbkspec*MasterKeyPartsSpec, instanceID string) error - Initializes crypto units

#### User Management

- ListUsers(cryptoUnitID string) ([]UserInfo, error) - Lists users on a crypto unit
- AddUser(cryptoUnitID string, req *AddUserRequest) error - Adds a user
- AddUserWithContext(ctx context.Context, cryptoUnitID string, req *AddUserRequest) error - Adds user with context
- AddKMSUser(ctx context.Context, cryptoUnitID string) ([]UserInfo, error) - Adds a KMS user
- DeleteUser(cryptoUnitID string, username string) error - Deletes a user
- DeleteUserWithContext(ctx context.Context, cryptoUnitID string, username string) error - Deletes user with context
- Key Management
- GenerateSignatureKey(instanceID string, req *SignatureKeyRequest) error - Generates a signature key
- ListMasterKeys(cryptoUnitID string) ([]MasterKeyInfo, error) - Lists master keys
- ListMasterKeysWithContext(ctx context.Context, cryptoUnitID string) ([]MasterKeyInfo, error) - Lists master keys with context
- GenerateMasterKey(cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) (string, error) - Generates a master key
- GenerateMasterKeyWithContext(ctx context.Context, cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) (string, error) - Generates master key with context
- ImportMasterKey(cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) error - Imports a master key
- ImportMasterKeyWithContext(ctx context.Context, cryptoUnitID string, request *MasterKeyPartsSpec) error - Imports master key with context
- ImportMasterKeyToCryptoUnits(ctx context.Context, cryptoUnitIDs []string, request *MasterKeyPartsSpec) error - Imports master key to multiple crypto units

#### Audit

- GetAuditLog(cryptoUnitID string) (*AuditLog, error) - Gets audit log

## Platform Support

- Linux (amd64, arm64)
- macOS (Intel, Apple Silicon)
- Windows (amd64)

## Requirements

### For Consumers (Using the Package)

- **Go 1.21 or later**
- **No CGO required** - `CGO_ENABLED=0` works fine!
- **No C compiler needed** - Pure Go builds

### For Maintainers (Building the Package)

- Go 1.21 or later
- CGO enabled (`CGO_ENABLED=1`)
- GCC or compatible C compiler
- Platform-specific toolchains for cross-compilation

### Runtime Dependencies

- Shared libraries are self-contained (OpenSSL 1.1 statically linked)
- No external dependencies required

## Support

For support, please contact:

- Email: <support@ibm.com>
- Documentation: <https://cloud.ibm.com/docs/key-protect>

## License

This software is provided under the IBM license agreement. Refer to the LICENSE file for terms and conditions.

### v1.0.0 (2026-04-10)

- Initial release
- Support for KeyProtect SingleTenant CryptoUnit
- Pre-compiled binaries for all major platforms
