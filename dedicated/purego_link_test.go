//go:build !disable_purego

package dedicated

import (
	"os"
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
