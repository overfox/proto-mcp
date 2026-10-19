package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Truncation to NAME_MAX never splits a multi-byte character, with or
// without an extension to preserve.
func TestFilename_TruncateOnRuneBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, in, wantExt string
	}{
		{"ext 3-byte", strings.Repeat("é", 10) + strings.Repeat("日", 100) + ".pdf", ".pdf"},
		{"ext 2-byte odd offset", "a" + strings.Repeat("é", 200) + ".txt", ".txt"},
		{"ext 4-byte", "ab" + strings.Repeat("😀", 100) + ".docx", ".docx"},
		{"no ext", "x" + strings.Repeat("日", 120), ""},
		{"long ext", "a." + strings.Repeat("日", 120), ""},
	} {
		got := Filename(tc.in)
		if !utf8.ValidString(got) {
			t.Errorf("%s: Filename produced invalid UTF-8 (%d bytes): %q", tc.name, len(got), got)
		}
		if len(got) > filenameMaxBytes {
			t.Errorf("%s: %d bytes > %d", tc.name, len(got), filenameMaxBytes)
		}
		if len(got) < filenameMaxBytes-3 {
			t.Errorf("%s: cut too much: %d bytes", tc.name, len(got))
		}
		if tc.wantExt != "" && !strings.HasSuffix(got, tc.wantExt) {
			t.Errorf("%s: extension lost: %q", tc.name, got)
		}
		if again := Filename(got); again != got {
			t.Errorf("%s: not idempotent: %q → %q", tc.name, got, again)
		}
	}
}
