package store

import (
	"errors"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// Time Machine exclusion (SECURITY M1). store.db and its WAL / SHM
// sidecars hold decrypted bodies and attachments; the retention purge
// is pointless if an hourly backup has already copied them to a disk
// that keeps snapshots for years. Marking the files the way
// `tmutil addexclusion <path>` does (a sticky, per-item exclusion, no
// root needed) keeps them out of future backups.

// backupExcludeXattr is the attribute tmutil addexclusion sets; its
// value is the binary plist encoding of the string "com.apple.backupd".
const backupExcludeXattr = "com.apple.metadata:com_apple_backup_excludeItem"

var backupExcludeValue = []byte{
	0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0x5f, 0x10, 0x11, 0x63, 0x6f, 0x6d, 0x2e, 0x61,
	0x70, 0x70, 0x6c, 0x65, 0x2e, 0x62, 0x61, 0x63, 0x6b, 0x75, 0x70, 0x64, 0x08, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
}

// ExcludeFromBackup marks path (file or directory) as excluded from
// Time Machine. A missing path is not an error.
func ExcludeFromBackup(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return unix.Setxattr(path, backupExcludeXattr, backupExcludeValue, 0)
}

// excludeStoreFromBackup applies ExcludeFromBackup to the database and
// its sidecars. Best-effort: failures are logged, never fatal.
func excludeStoreFromBackup(path string) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := ExcludeFromBackup(path + suffix); err != nil {
			slog.Warn("store: could not exclude from Time Machine", "path", path+suffix, "err", err.Error())
		}
	}
}
