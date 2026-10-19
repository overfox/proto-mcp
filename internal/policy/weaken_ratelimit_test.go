package policy

import (
	"strings"
	"testing"
)

func TestWeakeningsIncludeRateLimit(t *testing.T) {
	base := document{Tools: map[string]ToolPolicy{"mail_send": {Decision: DecisionPrompt, RateLimit: "20/hour"}}}
	merged := document{Tools: map[string]ToolPolicy{"mail_send": {Decision: DecisionPrompt}}}
	got := strings.Join(computeWeakenings(base, merged), "\n")
	if !strings.Contains(got, "rate_limit") {
		t.Fatalf("dropped rate_limit not reported as a weakening: %q", got)
	}
}
