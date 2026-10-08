package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Twigpine/twig/internal/identity"
)

func TestResolveNodeURLDefault(t *testing.T) {
	t.Setenv("TWIGPINE_NODE", "")
	t.Setenv("GITLAWB_NODE", "")

	if got := ResolveNodeURL(""); got != "https://node.gitlawb.com" {
		t.Fatalf("expected working public node, got %q", got)
	}
}

func TestSignRequestHeaders(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	body := []byte(`{"name":"test-repo"}`)
	method := "POST"
	path := "/api/v1/repos"

	digest, sigInput, sig := SignRequest(kp, method, path, body)

	if !strings.HasPrefix(digest, "sha-256=:") || !strings.HasSuffix(digest, ":") {
		t.Fatalf("invalid Content-Digest header: %s", digest)
	}

	if !strings.HasPrefix(sigInput, `sig1=("@method" "@path" "content-digest");keyid="`+kp.DID()+`"`) {
		t.Fatalf("invalid Signature-Input header: %s", sigInput)
	}

	if !strings.HasPrefix(sig, "sig1=:") || !strings.HasSuffix(sig, ":") {
		t.Fatalf("invalid Signature header: %s", sig)
	}

	// Verify the signature manually using standard RFC 9421 reconstruction
	sigB64 := strings.TrimSuffix(strings.TrimPrefix(sig, "sig1=:"), ":")
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	sigParamsValue := strings.TrimPrefix(sigInput, "sig1=")
	signingString := fmt.Sprintf("\"@method\": %s\n\"@path\": %s\n\"content-digest\": %s\n\"@signature-params\": %s",
		method, path, digest, sigParamsValue,
	)

	if !ed25519.Verify(kp.PublicKey, []byte(signingString), sigBytes) {
		t.Fatalf("signature did not verify over RFC 9421 signing string")
	}
}

func TestSanitizeNodeMsg(t *testing.T) {
	raw := "Hello\x1b[31mRed\x00World\u202EReverse"
	sanitized := SanitizeNodeMsg(raw)
	if strings.Contains(sanitized, "\x1b") || strings.Contains(sanitized, "\x00") || strings.Contains(sanitized, "\u202E") {
		t.Fatalf("sanitized message still contains control or bidi characters: %q", sanitized)
	}
	if !strings.Contains(sanitized, "Hello") || !strings.Contains(sanitized, "Red") {
		t.Fatalf("expected text missing: %q", sanitized)
	}
}

func TestClientSameOriginRedirect(t *testing.T) {
	var secondServer *httptest.Server
	secondServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("different origin"))
	}))
	defer secondServer.Close()

	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secondServer.URL, http.StatusFound)
	}))
	defer firstServer.Close()

	c := New(firstServer.URL, nil)
	resp, err := c.Get("/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should NOT follow cross-origin redirect
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected status 302 Found (not followed), got %d", resp.StatusCode)
	}
}

func TestSolveICaptchaURLValidation(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	c := New("https://example.com", kp)

	insecureURLs := []string{
		"http://attacker.com",
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1.attacker.com",
		"ftp://icaptcha.com",
		"file:///etc/passwd",
		"invalid-url",
	}

	for _, u := range insecureURLs {
		_, err := c.solveICaptcha(u, "1")
		if err == nil {
			t.Errorf("expected error for insecure/invalid URL %q, got nil", u)
		}
	}

	// Local http URLs should pass validation (and fail at connection level)
	_, err = c.solveICaptcha("http://127.0.0.1:12345", "1")
	if err == nil || strings.Contains(err.Error(), "insecure icaptcha server URL scheme") {
		t.Errorf("expected connection error for localhost http URL, got scheme error or nil: %v", err)
	}
}

func TestClientRedirectStripsSensitiveHeaders(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	var redirectedReq *http.Request
	var redirectServer *httptest.Server

	redirectServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirectedReq = r.Clone(r.Context())
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, redirectServer.URL+"/target", http.StatusFound)
	}))
	defer redirectServer.Close()

	c := New(redirectServer.URL, kp)

	req, err := http.NewRequest(http.MethodGet, redirectServer.URL+"/start", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Signature", "sig1=:abc:")
	req.Header.Set("Signature-Input", "sig1=(...)")
	req.Header.Set("Content-Digest", "sha-256=:123:")
	req.Header.Set("x-icaptcha-proof", "proof123")

	resp, err := c.Client.Do(req)
	if err != nil {
		t.Fatalf("client.Do failed: %v", err)
	}
	defer resp.Body.Close()

	if redirectedReq == nil {
		t.Fatalf("expected redirect target to receive request")
	}

	for _, header := range []string{"Signature", "Signature-Input", "Content-Digest", "x-icaptcha-proof"} {
		if val := redirectedReq.Header.Get(header); val != "" {
			t.Errorf("expected header %s to be stripped on redirect, got %q", header, val)
		}
	}
}
