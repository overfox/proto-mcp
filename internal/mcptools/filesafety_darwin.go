//go:build darwin

package mcptools

import (
	"bytes"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// kernelPath asks the kernel which path an open file descriptor refers
// to (fcntl F_GETPATH). On a case-insensitive volume this returns the
// name as stored on disk ("Application Support"), not the spelling the
// caller used to open it ("Application ſupport"), so the denylist can
// be re-run on ground truth after open.
func kernelPath(f *os.File) (string, error) {
	buf := new([unix.PathMax]byte)
	_, err := unix.FcntlInt(f.Fd(), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&buf[0]))))
	runtime.KeepAlive(buf)
	runtime.KeepAlive(f)
	if err != nil {
		return "", err
	}
	n := bytes.IndexByte(buf[:], 0)
	if n < 0 {
		n = len(buf)
	}
	return string(buf[:n]), nil
}
