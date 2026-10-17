package commands

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Twigpine/twig/internal/identity"
)

func TestIssueCommandsPathEscaping(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-issue-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	if err := identity.SaveKeypair(tempDir, kp); err != nil {
		t.Fatalf("failed to save keypair: %v", err)
	}

	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.RequestURI()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	// Test IssueShow with path traversal sequence in issue ID
	if err := IssueShow("owner/repo", "../evil/1", srv.URL, tempDir); err != nil {
		t.Fatalf("IssueShow failed: %v", err)
	}
	expectedPath := "/api/v1/repos/owner/repo/issues/..%2Fevil%2F1"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}

	// Test IssueClose with path traversal sequence in issue ID
	if err := IssueClose("owner/repo", "../evil/1", srv.URL, tempDir); err != nil {
		t.Fatalf("IssueClose failed: %v", err)
	}
	expectedPath = "/api/v1/repos/owner/repo/issues/..%2Fevil%2F1/close"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}

	// Test IssueComment with special characters in issue ID
	if err := IssueComment("owner/repo", "1#comment", "hello", srv.URL, tempDir); err != nil {
		t.Fatalf("IssueComment failed: %v", err)
	}
	expectedPath = "/api/v1/repos/owner/repo/issues/1%23comment/comments"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}

	// Test IssueList with special characters in repo name
	if err := IssueList("owner/repo?test=1", srv.URL, tempDir); err != nil {
		t.Fatalf("IssueList failed: %v", err)
	}
	expectedPath = "/api/v1/repos/owner/repo%3Ftest=1/issues"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}
