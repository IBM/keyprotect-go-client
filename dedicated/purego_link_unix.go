//go:build !windows && !disable_purego

package dedicated

import (
	"github.com/ebitengine/purego"
)

// openLibrary loads the shared library at path using POSIX dlopen.
// RTLD_LAZY defers symbol resolution until first use; RTLD_GLOBAL exports
// the library's symbols for subsequently loaded libraries to see.
func openLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
}
