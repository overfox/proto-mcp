//go:build !darwin

package mcptools

import (
	"errors"
	"os"
	"syscall"
)

// kernelPath is darwin-only (fcntl F_GETPATH); elsewhere the post-open
// re-check is skipped.
func kernelPath(*os.File) (string, error) {
	return "", errors.New("kernel path lookup not supported on this platform")
}

// statCtimeNs: the ctime field's name differs across the other
// platforms; 0 leaves the fingerprint at dev+inode+size+mtime there.
func statCtimeNs(*syscall.Stat_t) int64 { return 0 }
