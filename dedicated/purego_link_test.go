//go:build !disable_purego

package dedicated

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitLibrary tests initLibrary platform validation via resolveLibName.
// The TEST_GOOS and TEST_GOARCH environment variables drive each sub-test's
// platform/architecture values so that the test suite can be run on any host.
func TestInitLibrary(t *testing.T) {
	tests := []struct {
		name        string
		testGOOS    string
		testGOARCH  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "supported platform linux/amd64 succeeds platform check",
			testGOOS:   "linux",
			testGOARCH: "amd64",
			wantErr:    false,
		},
		{
			name:       "supported platform darwin/arm64 succeeds platform check",
			testGOOS:   "darwin",
			testGOARCH: "arm64",
			wantErr:    false,
		},
		{
			name:        "unsupported architecture darwin/amd64 returns error",
			testGOOS:    "darwin",
			testGOARCH:  "amd64",
			wantErr:     true,
			errContains: "unsupported architecture for darwin",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Set the test-scoped env vars so callers can inspect them,
			// and read them back as the GOOS/GOARCH under test.
			t.Setenv("TEST_GOOS", tt.testGOOS)
			t.Setenv("TEST_GOARCH", tt.testGOARCH)

			goos := os.Getenv("TEST_GOOS")
			goarch := os.Getenv("TEST_GOARCH")

			require.Equal(t, tt.testGOOS, goos, "TEST_GOOS env var should be set")
			require.Equal(t, tt.testGOARCH, goarch, "TEST_GOARCH env var should be set")

			_, err := resolveLibName(goos, goarch)

			if tt.wantErr {
				assert.Error(t, err, "resolveLibName should return an error for %s/%s", goos, goarch)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains,
						"error message should contain %q", tt.errContains)
				}
			} else {
				assert.NoError(t, err, "resolveLibName should not return an error for %s/%s", goos, goarch)
			}
		})
	}
}

func setupTestCacheDir(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	switch runtime.GOOS {
	case "darwin":
		t.Setenv("HOME", tempDir)
	case "windows":
		t.Setenv("LocalAppData", tempDir)
	default:
		t.Setenv("XDG_CACHE_HOME", tempDir)
	}
	cacheDir, err := os.UserCacheDir()
	require.NoError(t, err)
	return cacheDir
}

func TestSHA256Consistency(t *testing.T) {
	libName, err := resolveLibName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip("skipping on unsupported platform: ", err)
	}
	embeddedHash, err := embeddedLibSHA256(libName)
	if err != nil {
		t.Skip("embedded library not available: ", err)
	}
	require.NotEmpty(t, embeddedHash)

	platform := runtime.GOOS + "-" + runtime.GOARCH
	data, err := embeddedLibs.ReadFile(path.Join("internal/lib", platform, libName))
	require.NoError(t, err)

	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, libName)
	err = os.WriteFile(tempFilePath, data, 0600)
	require.NoError(t, err)

	fileHash, err := fileSHA256(tempFilePath)
	require.NoError(t, err)
	assert.Equal(t, embeddedHash, fileHash)
}

func TestVerifyLibSHA256(t *testing.T) {
	libName, err := resolveLibName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip("skipping on unsupported platform: ", err)
	}
	platform := runtime.GOOS + "-" + runtime.GOARCH
	data, err := embeddedLibs.ReadFile(path.Join("internal/lib", platform, libName))
	if err != nil {
		t.Skip("embedded library not available: ", err)
	}

	tempDir := t.TempDir()

	t.Run("passes for valid copy", func(t *testing.T) {
		validPath := filepath.Join(tempDir, "valid-"+libName)
		err := os.WriteFile(validPath, data, 0600)
		require.NoError(t, err)

		err = verifyLibSHA256(validPath, libName)
		assert.NoError(t, err)
	})

	t.Run("fails for tampered copy", func(t *testing.T) {
		tamperedPath := filepath.Join(tempDir, "tampered-"+libName)
		err := os.WriteFile(tamperedPath, []byte("tampered corrupted library contents"), 0600)
		require.NoError(t, err)

		err = verifyLibSHA256(tamperedPath, libName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mismatch")
	})

	t.Run("fails for nonexistent file", func(t *testing.T) {
		nonexistentPath := filepath.Join(tempDir, "nonexistent-"+libName)
		err := verifyLibSHA256(nonexistentPath, libName)
		assert.Error(t, err)
	})
}

func TestGetLibraryPath(t *testing.T) {
	libName, err := resolveLibName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip("skipping on unsupported platform: ", err)
	}

	t.Run("trusted=true when found via KEYPROTECT_LIB_PATH", func(t *testing.T) {
		envDir := t.TempDir()
		libPath := filepath.Join(envDir, libName)
		err := os.WriteFile(libPath, []byte("dummy-lib"), 0600)
		require.NoError(t, err)

		t.Setenv("KEYPROTECT_LIB_PATH", envDir)

		foundPath, trusted := getLibraryPath(libName)
		assert.Equal(t, libPath, foundPath)
		assert.True(t, trusted)
	})

	t.Run("trusted=false when found in cache dir", func(t *testing.T) {
		cacheDir := setupTestCacheDir(t)
		t.Setenv("KEYPROTECT_LIB_PATH", "")

		platform := runtime.GOOS + "-" + runtime.GOARCH
		cacheLibDir := filepath.Join(cacheDir, "lib", "ibm", platform)
		err := os.MkdirAll(cacheLibDir, 0700)
		require.NoError(t, err)

		libPath := filepath.Join(cacheLibDir, libName)
		err = os.WriteFile(libPath, []byte("dummy-lib"), 0600)
		require.NoError(t, err)

		foundPath, trusted := getLibraryPath(libName)
		assert.Equal(t, libPath, foundPath)
		assert.False(t, trusted)
	})

	t.Run("returns empty string and trusted=false when not found", func(t *testing.T) {
		setupTestCacheDir(t)
		t.Setenv("KEYPROTECT_LIB_PATH", t.TempDir()) // empty dir

		foundPath, trusted := getLibraryPath("nonexistent_lib_name.so")
		assert.Empty(t, foundPath)
		assert.False(t, trusted)
	})
}

func TestExtractEmbeddedLib(t *testing.T) {
	libName, err := resolveLibName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip("skipping on unsupported platform: ", err)
	}
	_, err = embeddedLibSHA256(libName)
	if err != nil {
		t.Skip("embedded library not available: ", err)
	}

	t.Run("extracts and overwrites corrupted existing file", func(t *testing.T) {
		cacheDir := setupTestCacheDir(t)
		platform := runtime.GOOS + "-" + runtime.GOARCH
		destDir := filepath.Join(cacheDir, "lib", "ibm", platform)
		err := os.MkdirAll(destDir, 0700)
		require.NoError(t, err)

		destFile := filepath.Join(destDir, libName)
		err = os.WriteFile(destFile, []byte("corrupted old cache content"), 0600)
		require.NoError(t, err)

		extractedPath, err := extractEmbeddedLib(libName)
		require.NoError(t, err)
		assert.Equal(t, destFile, extractedPath)

		// Verify the extracted file matches embedded hash
		err = verifyLibSHA256(extractedPath, libName)
		assert.NoError(t, err)
	})

	t.Run("extracts only current platform and leaves no tmp files", func(t *testing.T) {
		cacheDir := setupTestCacheDir(t)
		platform := runtime.GOOS + "-" + runtime.GOARCH

		extractedPath, err := extractEmbeddedLib(libName)
		require.NoError(t, err)
		assert.NotEmpty(t, extractedPath)

		ibmDir := filepath.Join(cacheDir, "lib", "ibm")
		entries, err := os.ReadDir(ibmDir)
		require.NoError(t, err)

		// Check that other platform directories are absent
		for _, entry := range entries {
			if entry.IsDir() {
				assert.Equal(t, platform, entry.Name(), "only current platform dir should exist")
			}
		}

		// Check destination dir for tmp leftovers
		destDir := filepath.Join(ibmDir, platform)
		destEntries, err := os.ReadDir(destDir)
		require.NoError(t, err)

		for _, entry := range destEntries {
			assert.NotContains(t, entry.Name(), ".tmp", "no temp files should be left over")
		}
	})
}
