package dedicated

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/IBM/go-sdk-core/v5/core"
)

// StateInfo represents the current state of the HSM
type SessionInfo struct {
	CryptoUnitID string
	UserName     string
	AuthState    uint32
}

func (s *SessionInfo) String() string {
	return fmt.Sprintf("SessionInfo{CryptoUnitID: %s, UserName: %s, AuthState: 0x%08x}",
		s.CryptoUnitID, s.UserName, s.AuthState)
}

// UserAttributes represents parsed HSM user attributes
type UserAttributes struct {
	// A[] - Application-depending attributes (e.g., CXI_GROUP=SLOT_0007)
	ApplicationAttrs map[string]string

	// H[] - Non-default hash algorithms (e.g., SHA-256)
	HashAlgorithm string

	// Z[] - Counter for consecutively failed authentication attempts
	FailedAuthCount int

	// L[] - PKCS#11 slot label
	SlotLabel string

	// I[] - User authentication state (0=can perform commands, 1=must change password)
	AuthState int

	// Raw - Original unparsed attribute string
	Raw string
}

// UserInfo represents information about an HSM user
type UserInfo struct {
	Username    string
	Permissions uint32
	Mechanism   string
	Attributes  UserAttributes
}

// CryptoUserMetadata represents metadata for a KMS crypto user
type CryptoUserMetadata struct {
	Username  string `json:"user_name"`
	PublicKey string `json:"public_key"`
	SlotID    int    `json:"slot_id"`
}

// AddUserRequest contains parameters for adding a new user
type AddUserRequest struct {
	Username   string
	Permission uint32
	Mechanism  string // "hmacpwd", "rsasign", or "ecdsa"
	CredHash   string //
	Attributes string // Optional attributes
	Token      string // Authentication token
}

// GenerateKeyRequest contains parameters for key generation
type GenerateKeyRequest struct {
	KeySpec     string // Key specification (file path or smart card identifier)
	KeySizeBits uint32 // Key size in bits (e.g., 2048, 3072, 4096)
	Owner       string // Key owner identifier
}

// SignatureKeyRequest contains parameters for signature key generation
type SignatureKeyRequest struct {
	// FilePath is the path where the signature key file will be saved
	// Must be 1-255 characters and point to an existing directory
	FilePath string

	// Passphrase is optional encryption for the key file
	// If provided, must be 4-255 characters
	// Empty string means no passphrase
	Passphrase string

	// Algorithm specifies the key algorithm
	// Currently only "RSA-2048" is supported
	Algorithm string

	// Owner is the optional key owner identifier passed to the underlying key generation call
	Owner string

	// Exists dictates if the signature key is an existing file from the FilePath
	Exists bool

	// Overwrite dictates if the signature key should be overwritten if the FilePath exists
	Overwrite bool
}

func NewSignatureKeyRequest(filepath, passphrase, owner string, exists, overwrite bool) (*SignatureKeyRequest, error) {
	err := validateFileSyntax(filepath)
	if err != nil {
		return nil, err
	}
	rootKeySpec := &SignatureKeyRequest{
		FilePath:   filepath,
		Passphrase: passphrase,
		Algorithm:  SigKeyAlgorithmRSA2048,
		Owner:      owner,
		Exists:     exists,
		Overwrite:  overwrite,
	}
	if err := validateSignatureKeyRequest(rootKeySpec); err != nil {
		return nil, err
	}
	return rootKeySpec, nil
}

// Signature key validation constants
const (
	SigKeyPassphraseMinLength = 4
	SigKeyPassphraseMaxLength = 255
	SigKeyFilePathMinLength   = 1
	SigKeyFilePathMaxLength   = 255
	SigKeyAlgorithmRSA2048    = "RSA-2048"
)

type contextKey string

const headersKey contextKey = "request-headers"

// MasterKeyInfo represents information about a Master Backup Key
type MasterKeyInfo struct {
	Slot           string // Slot number where the MBK is stored
	Name           string // Name of the MBK
	Len            string // Length of the key in bytes
	Algo           string // Algorithm (e.g., "AES")
	Type           string // Type (e.g., "SHARE")
	K              string // Threshold parameter (minimum shares needed)
	GenerationDate string // Date when the key was generated
	KeyCheckValue  string // Key check value for verification
}

// MasterKeyRequest contains parameters for generating a Master Backup Key
type MasterKeyRequest struct {
	// KeySpec specifies the key specification (e.g., file path or identifier)
	KeySpec string

	// KeyType specifies the type of key (e.g., "RSA", "AES")
	KeyType string

	// KeyLength specifies the key length in bits
	KeyLength int

	// N is the threshold parameter (minimum number of key parts required)
	N uint8

	// K is the total number of key parts to generate
	K uint8

	// KeyName is the name/identifier for the generated MBK
	KeyName string
}

// MasterKeyPartsSpec represents a key specification for generating a Master Key as parts
type MasterKeyPartsSpec struct {
	// K is the threshold parameter (minimum number of key parts required)
	K uint8

	// KeyName is the name/identifier for the generated MBK
	KeyName string

	// KeyShareFiles is a slice of MBK key part file specifications with passphrases
	// Format: []string{"filepath_0.key#passphrase", "filepath_1.key#passphrase"}
	// This will be converted to comma-separated string
	KeyShareFiles []string

	// SlotNo is the slot number where the MBK will be imported (0-based)
	SlotNo int

	// Exists determines if the master key parts files in KeyShareFiles are existing files.
	Exists bool

	// Overwrite dictates if the master key parts should be overwritten if the KeyShareFiles exists
	Overwrite bool
}

// NewMasterKeyPartsSpec creates a NewMasterKeyPartsSpec for the client
//
// k is the threshold parameter (minimum number of key parts required)
//
// keyName is the name/identifier for the generated MBK
//
// keyShareFiles is a slice of MBK key part file specifications with passphrases
// Format: []string{"filepath_0.key#passphrase", "filepath_1.key#passphrase"}
//
// shouldGen is a bool to determine to use the existing files specified in
// the keysharefiles field
func NewMasterKeyPartsSpec(k int, keyName string, keysharefiles []string, exists, overwrite bool) (*MasterKeyPartsSpec, error) {
	// Validate K is within uint8 range
	if k < 0 || k > 255 {
		return nil, fmt.Errorf("k value %d is out of range (0-255)", k)
	}
	mkps := &MasterKeyPartsSpec{
		K:             uint8(k),
		KeyName:       keyName,
		KeyShareFiles: keysharefiles,
		SlotNo:        3,
		Exists:        exists,
		Overwrite:     overwrite,
	}
	if err := validateMasterKeyPartsSpec(mkps); err != nil {
		return nil, err
	}
	return mkps, nil
}

// ImportMasterKeyResult represents the result of importing an MBK to a crypto unit
type ImportMasterKeyResult struct {
	CryptoUnitID string
	Error        error
}

// AuditLog represents the HSM audit log
type AuditLog struct {
	Entries []AuditEntry
	Raw     string
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp string
	User      string
	Action    string
	Result    string
	Details   string
}

// ReturnFormat flags for response formatting
const (
	RetFormatHR   = 0x00000001 // Human readable response
	RetFormatHex  = 0x00000002 // HEX Encoded HR response
	RetFormatBin  = 0x00000004 // Byte array (raw response from device)
	RetFormatXML  = 0x00000010 // XML formatted response
	RetFormatJSON = 0x00000020 // JSON formatted response
	RetFormatAlt  = 0x00000040 // Alternate format (command-specific)
)

// KeyType constants
const (
	KeyTypeRSA   = 1
	KeyTypeECDSA = 2
)

// HSM Filesystem constants
const (
	HSMFsAll   = 0
	HSMFsNVRAM = 1
	HSMFsFlash = 2
)

// CryptoUnitClaimRequest contains parameters for claiming a crypto unit
type CryptoUnitClaimRequest struct {
	// SignatureKeyPath is the path to the signature key file generated by GenerateSignatureKey
	// The file should contain MOD and PEXP values in hexadecimal format
	SignatureKeyPath string

	// CryptoUnitIDs is an optional list of specific crypto unit IDs to claim
	// If nil or empty, all crypto units in the instance will be claimed
	CryptoUnitIDs []string
}

// CryptoUnitClaimBody contains the public key for claiming a crypto unit (internal use)
type CryptoUnitClaimBody struct {
	PublicKey string `json:"certificate"`
}

// CryptoUnitState represents the state of a crypto unit
type CryptoUnitState string

// CryptoUnit state constants
const (
	CryptoUnitStateAvailable      CryptoUnitState = "available"
	CryptoUnitStateReserved       CryptoUnitState = "reserved"
	CryptoUnitStateClaimed        CryptoUnitState = "claimed"
	CryptoUnitStateKMSAuthorized  CryptoUnitState = "kms-authorized"
	CryptoUnitStateInitialized    CryptoUnitState = "initialized"
	CryptoUnitStateKMSInitialized CryptoUnitState = "kms-initialized"
	CryptoUnitStateMarkedForDel   CryptoUnitState = "marked-for-del"
	CryptoUnitStateZeroized       CryptoUnitState = "zeroized"
	CryptoUnitStateMaintenance    CryptoUnitState = "maintenance"
)

type CryptoUnit struct {
	ID         string          `json:"id"`
	InstanceID string          `json:"instanceId"`
	State      CryptoUnitState `json:"state"`
}

type CryptoUnits struct {
	CryptoUnits []CryptoUnit `json:"crypto_units,omitempty"`
}

func (cus *CryptoUnits) IDs() []string {
	// Pre-allocate slice for performance
	ids := make([]string, len(cus.CryptoUnits))
	for i, u := range cus.CryptoUnits {
		ids[i] = u.ID
	}
	return ids
}

// LoginSpec represents the login specification for a cryptounit
type LoginSpec struct {
	// KeyFile is a key file specification with a passphrase, separated with a '#'
	// Format: "filepath_0.key#passphrase"
	KeyFile string `json:"-"`

	// The unique id given for a cryptounit
	CryptoUnitID string `json:"cryptounit_id"`

	// The port to connect to a cryptounit
	Port int `json:"port"`

	// The username to identify as
	Username string `json:"username"`
}

// session represents a cryptounit session
type session struct {
	id           uintptr
	CryptoUnitID string
	Username     string
}

// newSession creates a new session object with a valid pointer and non-empty fields
func newSession(id uintptr, cuid, userName string) (*session, error) {
	if id == 0 || unsafe.Pointer(id) == nil {
		return nil, fmt.Errorf("session object cannot have a nil pointer")
	}
	if cuid == "" {
		return nil, fmt.Errorf("session object cannot contain a empty cryptounit id")
	}
	if userName == "" {
		return nil, fmt.Errorf("session object cannot an empty username")
	}
	return &session{
		id:           id,
		CryptoUnitID: cuid,
		Username:     userName,
	}, nil
}

func (s *session) String() string {
	return fmt.Sprintf("session{CryptoUnitID: %s, Username: %s}", s.CryptoUnitID, s.Username)
}

// SessionPool holds all the cryptounits sessions created
type SessionPool struct {
	mu       sync.Mutex
	sessions map[string]*session
	logger   core.Logger
}

func newSessionPool(logger core.Logger) *SessionPool {
	return &SessionPool{
		sessions: make(map[string]*session),
		logger:   logger,
	}
}

// Add inserts a valid session to a cryptounit
func (p *SessionPool) add(s *session) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Don't use get for add
	if s, exists := p.sessions[s.CryptoUnitID]; exists {
		return fmt.Errorf("connection to cryptounit %s exists", s.CryptoUnitID)
	}
	p.sessions[s.CryptoUnitID] = s
	return nil
}

// get will determine if there is a session to the cryptoUnitID already present
func (p *SessionPool) get(cryptoUnitID string) (*session, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, exists := p.sessions[cryptoUnitID]
	return s, exists
}

// Disconnect will call the close session to the HSM
func (p *SessionPool) disconnect(cryptoUnitID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sess, exists := p.sessions[cryptoUnitID]
	if !exists {
		return nil
	}
	err := callCloseSession(sess.id)
	if err != nil {
		return err
	}
	delete(p.sessions, cryptoUnitID)
	return nil
}

// DisconnectAll will disconnect all sessions in the pool
func (p *SessionPool) disconnectAll() {
	if len(p.sessions) == 0 {
		return
	}
	p.logger.Debug("Disconnecting all cryptounit sessions")
	for id := range p.sessions {
		if err := p.disconnect(id); err != nil {
			p.logger.Error(fmt.Sprintf("Session Pool encountered a problem closing session for cryptounit %s: %s", id, err.Error()))
		}
	}
	p.logger.Info("Disconnected from all cryptounits")
}

// GetConnectedCryptoUnits will return a list of all connected crypto units
func (p *SessionPool) GetConnectedCryptoUnits() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	cryptounits := make([]string, len(p.sessions))
	for cuID := range p.sessions {
		cryptounits = append(cryptounits, cuID)
	}
	return cryptounits
}
