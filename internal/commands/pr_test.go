package commands

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestPrCreateSendsBranchFields enforces the node API schema: PR creation
// must send source_branch/target_branch, never head/base.
func TestPrCreateSendsBranchFields(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-pr-*")
	if err != nil {
		t.Fatalf("tempdir failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var stdin bytes.Buffer
	if err := IdentityNew(tempDir, true, &stdin); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}

	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/repos/owner/repo/pulls" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		// Server schema: source_branch required, target_branch optional,
		// head/base are not recognized.
		if _, ok := got["head"]; ok {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"unexpected field: head"}`))
			return
		}
		if _, ok := got["base"]; ok {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"unexpected field: base"}`))
			return
		}
		if got["source_branch"] != "feat" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"source_branch required"}`))
			return
		}
		if got["target_branch"] != "main" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"target_branch mismatch"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":1,"title":"T"}`))
	}))
	defer srv.Close()

	// Empty base defaults to "main".
	if err := PrCreate("owner/repo", "feat", "", "T", "B", "", srv.URL, tempDir); err != nil {
		t.Fatalf("PrCreate failed: %v", err)
	}
	if got["source_branch"] != "feat" || got["target_branch"] != "main" {
		t.Fatalf("unexpected payload: %v", got)
	}
}

func TestPrCreateOptionInjection(t *testing.T) {
	tempDir := t.TempDir()
	var stdin bytes.Buffer
	if err := IdentityNew(tempDir, true, &stdin); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}

	cases := []struct {
		name          string
		head          string
		base          string
		ownerOverride string
		wantErr       string
	}{
		{name: "flag head", head: "-flag", base: "main", wantErr: "invalid source branch \"-flag\": branch cannot start with '-'"},
		{name: "flag base", head: "feat", base: "-target", wantErr: "invalid target branch \"-target\": branch cannot start with '-'"},
		{name: "flag owner", head: "feat", base: "main", ownerOverride: "-badowner", wantErr: "invalid owner \"-badowner\": owner cannot start with '-'"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := PrCreate("owner/repo", tc.head, tc.base, "Title", "Body", tc.ownerOverride, "https://node.example.com", tempDir)
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("expected error %q, got %v", tc.wantErr, err)
			}
		})
	}
}
