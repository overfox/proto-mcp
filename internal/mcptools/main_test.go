package mcptools

import (
	"os"
	"runtime"
	"testing"
)

// Test hooks for the extraction child (attachment_text_extract.go):
// the test binary doubles as the child, the way protonmcpd does. These
// env vars only reach the child when a test puts them in
// extractChildEnv.
const (
	testChildHangEnv = "PROTO_MCP_TEST_EXTRACT_HANG=1"
	testChildHogEnv  = "PROTO_MCP_TEST_EXTRACT_HOG=1"
	testChildCPU1Env = "PROTO_MCP_TEST_EXTRACT_CPU1=1"
)

func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == ExtractTextSubcommand {
		if hasEnv(testChildCPU1Env) {
			extractChildCPUSeconds = 1
		}
		switch {
		case hasEnv(testChildHangEnv):
			extractTextFn = func(string, []byte, int) (string, error) {
				for { // a parser that never returns
					runtime.Gosched()
				}
			}
		case hasEnv(testChildHogEnv):
			extractTextFn = func(string, []byte, int) (string, error) {
				var keep [][]byte
				for {
					b := make([]byte, 64<<20)
					for i := range b {
						b[i] = 1
					}
					keep = append(keep, b)
				}
			}
		}
	}
	MaybeRunExtractTextChild()
	os.Exit(m.Run())
}

func hasEnv(kv string) bool {
	for _, e := range os.Environ() {
		if e == kv {
			return true
		}
	}
	return false
}
