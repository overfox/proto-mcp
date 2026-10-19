//go:build !darwin

package mcptools

import (
	"errors"
	"os"
)

// kernelPath is darwin-only (fcntl F_GETPATH); elsewhere the post-open
// re-check is skipped.
func kernelPath(*os.File) (string, error) {
	return "", errors.New("kernel path lookup not supported on this platform")
}
