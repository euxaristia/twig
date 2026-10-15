package commands

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Twigpine/twig/internal/identity"
)

func TestWebhookCommandsPathEscaping(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-webhook-*")
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

	// Test WebhookDelete with path traversal in webhook ID
	if err := WebhookDelete("owner/repo", "../evil/id", srv.URL, tempDir); err != nil {
		t.Fatalf("WebhookDelete failed: %v", err)
	}
	expectedPath := "/api/v1/repos/owner/repo/webhooks/..%2Fevil%2Fid"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}

	// Test WebhookList with special chars in repo name
	if err := WebhookList("owner/repo#special", srv.URL, tempDir); err != nil {
		t.Fatalf("WebhookList failed: %v", err)
	}
	expectedPath = "/api/v1/repos/owner/repo%23special/webhooks"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}

	// Test WebhookCreate with special chars in repo name
	if err := WebhookCreate("owner/repo?query=1", "https://example.com/hook", "push", "secret", srv.URL, tempDir); err != nil {
		t.Fatalf("WebhookCreate failed: %v", err)
	}
	expectedPath = "/api/v1/repos/owner/repo%3Fquery=1/webhooks"
	if capturedPath != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, capturedPath)
	}
}
