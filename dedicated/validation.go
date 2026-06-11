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

	if req.Exists && !req.Overwrite {
		if err := checkFileExists(req.FilePath); err != nil {
			return fmt.Errorf("directory does not exist: %s", req.FilePath)
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
		if err := checkFileExists(filePath); err != nil && mKeySpec.Exists && !mKeySpec.Overwrite {
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
