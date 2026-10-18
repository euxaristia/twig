package commands

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestIssueCommandsURLEscaped(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-issue-*")
	if err != nil {
		t.Fatalf("tempdir failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var stdin bytes.Buffer
	if err := IdentityNew(tempDir, true, &stdin); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}

	requestedURIs := make(map[string]bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURIs[r.RequestURI] = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	defer srv.Close()

	// An untrusted issueID containing a slash (e.g., "1/close" or "issue/1")
	// should be URL-path escaped to "1%2Fclose" instead of creating a nested path /1/close.
	issueID := "1/close"

	if err := IssueShow("owner/repo", issueID, srv.URL, tempDir); err != nil {
		t.Fatalf("IssueShow failed: %v", err)
	}
	expectedShowPath := "/api/v1/repos/owner/repo/issues/1%2Fclose"
	if !requestedURIs[expectedShowPath] {
		t.Errorf("expected request URI %q, got requested URIs: %v", expectedShowPath, requestedURIs)
	}

	if err := IssueClose("owner/repo", issueID, srv.URL, tempDir); err != nil {
		t.Fatalf("IssueClose failed: %v", err)
	}
	expectedClosePath := "/api/v1/repos/owner/repo/issues/1%2Fclose/close"
	if !requestedURIs[expectedClosePath] {
		t.Errorf("expected request URI %q, got requested URIs: %v", expectedClosePath, requestedURIs)
	}
}
