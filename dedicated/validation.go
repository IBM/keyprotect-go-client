package dedicated

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// validateSignatureKeyRequest validates the signature key generation request
func validateSignatureKeyRequest(req *SignatureKeyRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	// Validate file path
	if err := validateFileSyntax(req.FilePath); err != nil {
		return err
	}
	if len(req.FilePath) < SigKeyFilePathMinLength || len(req.FilePath) > SigKeyFilePathMaxLength {
		return fmt.Errorf("file path length must be between %d and %d characters",
			SigKeyFilePathMinLength, SigKeyFilePathMaxLength)
	}
	if strings.HasPrefix(req.FilePath, "./") {
		return fmt.Errorf("file path cannot start with './'")
	}

	// Validate directory exists if path contains separators
	if strings.Contains(req.FilePath, "/") || strings.Contains(req.FilePath, "\\") {
		dir := filepath.Dir(req.FilePath)
		if dir != "." && dir != "" {
			if err := checkFileExists(dir); err != nil {
				return fmt.Errorf("directory does not exist: %q", dir)
			}
		}
	}

	// Validate passphrase
	if req.Passphrase != "" {
		if len(req.Passphrase) < SigKeyPassphraseMinLength ||
			len(req.Passphrase) > SigKeyPassphraseMaxLength {
			return fmt.Errorf("passphrase length must be 0 or between %d and %d characters",
				SigKeyPassphraseMinLength, SigKeyPassphraseMaxLength)
		}
	}

	// Validate algorithm
	if req.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if req.Algorithm != SigKeyAlgorithmRSA2048 {
		return fmt.Errorf("only %s algorithm is supported", SigKeyAlgorithmRSA2048)
	}

	return nil
}

func validateMasterKeyPartsSpec(mKeySpec *MasterKeyPartsSpec) error {
	if len(mKeySpec.KeyShareFiles) < 2 {
		return fmt.Errorf("array of Keysharefiles cannot be less than 2")
	}
	for i, keyShareFile := range mKeySpec.KeyShareFiles {
		parts := strings.Split(keyShareFile, "#")
		filePath := parts[0]
		if err := validateFileSyntax(filePath); err != nil {
			return fmt.Errorf("KeyShareFiles[%d]: invalid path: %w", i, err)
		}
		if err := checkFileExists(filePath); err != nil && mKeySpec.Exists {
			return fmt.Errorf("KeyShareFiles[%d]: invalid file specified: %w", i, err)
		}
	}

	if mKeySpec.KeyName == "" {
		return fmt.Errorf("keyName cannot be empty")
	}
	if len(mKeySpec.KeyName) > 8 {
		return fmt.Errorf("keyName cannot be longer than 8 characters")
	}
	if int(mKeySpec.K) > len(mKeySpec.KeyShareFiles) {
		return fmt.Errorf("the value K (threshold: %d) cannot be greater than N (total parts: %d). K must be <= N", mKeySpec.K, len(mKeySpec.KeyShareFiles))
	}
	if mKeySpec.K < 2 {
		return fmt.Errorf("the value K (threshold) must be at least 2")
	}
	return nil
}

// validateAdditionalAdmins validates a list of additional admins against the
// initial admin key and the threshold configuration. initial and threshold
// may be nil to skip the corresponding checks.
func validateAdditionalAdmins(admins []*AdditionalAdminRequest, initial *SignatureKeyRequest, threshold *ThresholdRequest) error {
	names := map[string]struct{}{}
	paths := map[string]struct{}{}
	if initial != nil {
		paths[filepath.Clean(initial.FilePath)] = struct{}{}
	}
	for i, a := range admins {
		if a == nil {
			return fmt.Errorf("additional_admin[%d] cannot be nil", i)
		}
		if _, err := a.SignatureKeyRequest(); err != nil {
			return fmt.Errorf("additional_admin[%d]: %w", i, err)
		}
		if a.Name == initialAdminUsername {
			return fmt.Errorf("additional_admin[%d]: name %q is reserved for the initial admin", i, a.Name)
		}
		if _, dup := names[a.Name]; dup {
			return fmt.Errorf("additional_admin[%d]: duplicate name %q", i, a.Name)
		}
		names[a.Name] = struct{}{}
		p := filepath.Clean(a.FilePath)
		if _, dup := paths[p]; dup {
			return fmt.Errorf("additional_admin[%d]: duplicate key file path %q", i, a.FilePath)
		}
		paths[p] = struct{}{}
	}
	if threshold != nil {
		total := len(admins)
		if initial != nil {
			total++
		}
		needed := max(threshold.SignatureThreshold, threshold.RevocationThreshold)
		if total < needed {
			return fmt.Errorf("insufficient admins: have %d, need at least %d for the configured thresholds", total, needed)
		}
		// The quorum session is only opened when the threshold is applied.
		if thresholdNeedsSetting(threshold) {
			signers := len(quorumSessionAuths(initial, admins, total))
			if signers < needed {
				return fmt.Errorf("insufficient quorum signers: have %d, need at least %d for the configured thresholds", signers, needed)
			}
		}
	}
	return nil
}

// validateThreshold validates that both threshold values are within the allowed range
func validateThreshold(signatureThreshold, revocationThreshold int) error {
	if signatureThreshold < MinThreshold || signatureThreshold > MaxThreshold {
		return fmt.Errorf("signature-threshold must be between %d and %d, got: %d", MinThreshold, MaxThreshold, signatureThreshold)
	}

	if revocationThreshold < MinThreshold || revocationThreshold > MaxThreshold {
		return fmt.Errorf("revocation-threshold must be between %d and %d, got: %d", MinThreshold, MaxThreshold, revocationThreshold)
	}

	return nil
}

// validateThresholdAdminCount validates that the crypto unit has enough admins
// to satisfy the requested thresholds
func validateThresholdAdminCount(users []UserInfo, signatureThreshold, revocationThreshold int) error {
	totalAdmins := 0
	for _, u := range users {
		if u.Permissions == AdminPermission {
			totalAdmins++
		}
	}

	needed := max(signatureThreshold, revocationThreshold)
	if totalAdmins < needed {
		return fmt.Errorf("insufficient admin count: have %d admins, need at least %d (signature-threshold=%d, revocation-threshold=%d)",
			totalAdmins, needed, signatureThreshold, revocationThreshold)
	}

	return nil
}

// checkFileExists returns an error if the file at path does not exist or
// cannot be stat'd. Use this when the caller asserts the file must already
// be present (e.g. MasterKeyPartsSpec.Exists = true).
func checkFileExists(path string) error {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return nil // file is present — good
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("file does not exist at %q", path)
	default:
		return fmt.Errorf("unable to check file %q: %w", path, err)
	}
}

func validateFileSyntax(path string) error {
	// Clean resolves relative paths like "." or ".."
	cleaned := filepath.Clean(path)

	// Optional: Reject completely empty inputs
	if cleaned == "." && path == "" {
		return fmt.Errorf("filepath %s is not valid", path)
	}
	return nil
}
