//go:build windows && !disable_purego

package dedicated

import (
	"fmt"
	"syscall"
)

// openLibrary loads the shared library at path using the Windows LoadLibraryW API.
// This is the Windows equivalent of POSIX dlopen. The returned handle is a uintptr
// that is compatible with purego.RegisterLibFunc.
//
// Note: purego.Dlopen and purego.RTLD_LAZY/purego.RTLD_GLOBAL are not available on
// Windows; the Windows loader resolves all DLL exports eagerly at load time.
func openLibrary(path string) (uintptr, error) {
	handle, err := syscall.LoadLibrary(path)
	if err != nil {
		return 0, fmt.Errorf("LoadLibrary(%q): %w", path, err)
	}
	return uintptr(handle), nil
}
