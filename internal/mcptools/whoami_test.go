package mcptools

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

func TestAccountWhoami_PlanFromOrganization(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/core/v4/organizations" {
			http.NotFound(w, r)
			return
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":1000,"Organization":{"Name":"x","DisplayName":"X","PlanName":"bundle2022","MaxMembers":1}}`))
	}))
	defer srv.Close()
	mgr := gpa.New(gpa.WithHostURL(srv.URL))
	defer mgr.Close()
	sess := &protonclient.Session{
		Client:    mgr.NewClient("uid", "acc", "ref"),
		User:      gpa.User{ID: "user-plan-test", DisplayName: "Farid"},
		Addresses: []gpa.Address{{Email: "f@proton.me", Status: gpa.AddressStatusEnabled, Order: 1}},
	}
	var out struct {
		Email string `json:"email"`
		Plan  string `json:"plan"`
	}
	for i := 0; i < 2; i++ {
		callTool(t, accountWhoami(Deps{Session: sess}), `{}`, &out)
		if out.Plan != "bundle2022" || out.Email != "f@proton.me" {
			t.Errorf("whoami = %+v", out)
		}
	}
	if calls != 1 {
		t.Errorf("organization lookups = %d, want 1 (cached)", calls)
	}
}

func TestAccountWhoami_FreeAccountOmitsPlan(t *testing.T) {
	f := newFakeProton(t) // the fake server has no organizations endpoint
	var out map[string]any
	res := callTool(t, accountWhoami(f.deps()), `{}`, &out)
	if res.IsError {
		t.Fatal(res.Content[0].Text)
	}
	if _, ok := out["plan"]; ok {
		t.Errorf("plan should be omitted without an organization: %v", out)
	}
	if out["email"] == "" {
		t.Error("email missing")
	}
}
