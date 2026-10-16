package commands

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIdentityNewShowSignExport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-cmd-*")
	if err != nil {
		t.Fatalf("tempdir failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// IdentityNew
	var stdin bytes.Buffer
	if err := IdentityNew(tempDir, false, &stdin); err != nil {
		t.Fatalf("IdentityNew error: %v", err)
	}

	keyPath := filepath.Join(tempDir, "identity.pem")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("identity.pem was not created: %v", err)
	}

	// IdentityShow
	if err := IdentityShow(tempDir); err != nil {
		t.Fatalf("IdentityShow error: %v", err)
	}

	// IdentityExport
	if err := IdentityExport(tempDir); err != nil {
		t.Fatalf("IdentityExport error: %v", err)
	}

	// IdentitySign
	if err := IdentitySign(tempDir, "hello twigpine"); err != nil {
		t.Fatalf("IdentitySign error: %v", err)
	}

	// IdentityBackup & Restore
	bakPath := filepath.Join(tempDir, "identity.pem.bak")
	if err := IdentityBackup(tempDir, bakPath); err != nil {
		t.Fatalf("IdentityBackup error: %v", err)
	}
	if runtime.GOOS != "windows" {
		bakInfo, err := os.Stat(bakPath)
		if err != nil {
			t.Fatalf("stat bakPath failed: %v", err)
		}
		if perm := bakInfo.Mode().Perm(); perm != 0600 {
			t.Errorf("IdentityBackup file perm = %o, want 0600", perm)
		}
	}

	if err := IdentityRestore(tempDir, bakPath, true, strings.NewReader("y\n")); err != nil {
		t.Fatalf("IdentityRestore error: %v", err)
	}
}

func TestUcanDelegateFilePermissions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-ucan-*")
	if err != nil {
		t.Fatalf("tempdir failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var stdin bytes.Buffer
	if err := IdentityNew(tempDir, false, &stdin); err != nil {
		t.Fatalf("IdentityNew error: %v", err)
	}

	outPath := filepath.Join(tempDir, "delegated_ucan.json")

	// Test 1: New file creation
	if err := UcanDelegate("did:key:z6Mkq...", "repo/1", "git:push", 24, outPath, tempDir, false); err != nil {
		t.Fatalf("UcanDelegate error: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(outPath)
		if err != nil {
			t.Fatalf("stat failed: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("UcanDelegate file perm = %o, want 0600", perm)
		}
	}

	// Test 2: Pre-existing file with loose permissions (0666 / 0644)
	if err := os.WriteFile(outPath, []byte("loose data"), 0666); err != nil {
		t.Fatalf("failed writing loose file: %v", err)
	}
	if err := os.Chmod(outPath, 0666); err != nil {
		t.Fatalf("failed setting loose permissions: %v", err)
	}

	if err := UcanDelegate("did:key:z6Mkq...", "repo/1", "git:push", 24, outPath, tempDir, false); err != nil {
		t.Fatalf("UcanDelegate overwrite error: %v", err)
	}

	if runtime.GOOS != "windows" {
		infoOverwritten, err := os.Stat(outPath)
		if err != nil {
			t.Fatalf("stat failed: %v", err)
		}
		if perm := infoOverwritten.Mode().Perm(); perm != 0600 {
			t.Errorf("UcanDelegate overwritten file perm = %o, want 0600", perm)
		}
	}
}

func TestRegisterAndWhoami(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-reg-*")
	if err != nil {
		t.Fatalf("tempdir failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var in bytes.Buffer
	if err := IdentityNew(tempDir, true, &in); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/register" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Welcome to Twigpine","ucan":"eyJhbGciOiJFZERTQTEwMCJ9.test","trust_score":0.85,"expires":"2027-01-01"}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/agents/") && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"trust_score":0.85,"capabilities":["git:push","pr:open"]}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/repos") && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"name":"repo1"},{"name":"repo2"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if err := Register(srv.URL, []string{"git:push"}, "test-model", tempDir); err != nil {
		t.Fatalf("Register error: %v", err)
	}

	if err := Whoami(srv.URL, tempDir, true); err != nil {
		t.Fatalf("Whoami json error: %v", err)
	}

	if err := Whoami(srv.URL, tempDir, false); err != nil {
		t.Fatalf("Whoami text error: %v", err)
	}
}

func TestTrustBarVectors(t *testing.T) {
	cases := []struct {
		score    float64
		expected string
	}{
		{0.0, "░░░░"},
		{0.25, "█░░░"},
		{0.5, "██░░"},
		{0.75, "███░"},
		{1.0, "████"},
	}

	for _, c := range cases {
		got := TrustBar(c.score)
		if got != c.expected {
			t.Errorf("TrustBar(%v) = %q, want %q", c.score, got, c.expected)
		}
	}
}

func TestParseTwigpineURLVectors(t *testing.T) {
	// gitlawb://
	didPart, repo, ok := ParseTwigpineURL("gitlawb://did:key:z6Mk1234/myrepo")
	if !ok || didPart != "did:key:z6Mk1234" || repo != "myrepo" {
		t.Fatalf("failed parsing gitlawb URL: did=%s, repo=%s, ok=%v", didPart, repo, ok)
	}

	// gitlawb:// with newline
	didPart, repo, ok = ParseTwigpineURL("gitlawb://did:key:z6Mk1234/myrepo\n")
	if !ok || didPart != "did:key:z6Mk1234" || repo != "myrepo" {
		t.Fatalf("failed parsing gitlawb URL with newline: did=%s, repo=%s, ok=%v", didPart, repo, ok)
	}

	// twigpine:// with dash
	didPart, repo, ok = ParseTwigpineURL("twigpine://did:key:z6MkAbc/my-cool-repo")
	if !ok || didPart != "did:key:z6MkAbc" || repo != "my-cool-repo" {
		t.Fatalf("failed parsing twigpine URL with dash: did=%s, repo=%s, ok=%v", didPart, repo, ok)
	}

	// Non-gitlawb URL returns false
	if _, _, ok := ParseTwigpineURL("https://github.com/user/repo"); ok {
		t.Errorf("expected false for https github url")
	}
	if _, _, ok := ParseTwigpineURL("git@github.com:user/repo.git"); ok {
		t.Errorf("expected false for ssh git url")
	}

	// Empty repo or missing slash returns false
	if _, _, ok := ParseTwigpineURL("gitlawb://did:key:z6Mk1234/"); ok {
		t.Errorf("expected false for empty repo")
	}
	if _, _, ok := ParseTwigpineURL("gitlawb://did:key:z6Mk1234"); ok {
		t.Errorf("expected false for missing slash")
	}
}

func TestURLPathEscapingInCommands(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "twig-test-escaped-*")
	if err != nil {
		t.Fatalf("tempdir failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var in bytes.Buffer
	if err := IdentityNew(tempDir, true, &in); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}

	var requestedRawPaths []string
	var requestedRawQueries []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath := r.URL.RawPath
		if rawPath == "" {
			rawPath = r.URL.Path
		}
		requestedRawPaths = append(requestedRawPaths, rawPath)
		requestedRawQueries = append(requestedRawQueries, r.URL.RawQuery)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	// 1. Test IssueShow with path traversal in owner/name/issueID
	_ = IssueShow("owner/repo#name", "../1/close", srv.URL, tempDir)
	if len(requestedRawPaths) == 0 {
		t.Fatal("expected request for IssueShow")
	}
	lastPath := requestedRawPaths[len(requestedRawPaths)-1]
	wantSub := "/api/v1/repos/owner/repo%23name/issues/..%2F1%2Fclose"
	if lastPath != wantSub {
		t.Errorf("IssueShow path = %q, want %q", lastPath, wantSub)
	}

	// 2. Test ProtectSet with slash in branch
	_ = ProtectSet("feat/subbranch", "owner/repo", srv.URL, tempDir)
	lastPath = requestedRawPaths[len(requestedRawPaths)-1]
	wantSub = "/api/v1/repos/owner/repo/branches/feat%2Fsubbranch/protect"
	if lastPath != wantSub {
		t.Errorf("ProtectSet path = %q, want %q", lastPath, wantSub)
	}

	// 3. Test AgentShow with slash in targetDID
	_ = AgentShow("did:key:123/sub", srv.URL)
	lastPath = requestedRawPaths[len(requestedRawPaths)-1]
	wantSub = "/api/v1/agents/did:key:123%2Fsub"
	if lastPath != wantSub {
		t.Errorf("AgentShow path = %q, want %q", lastPath, wantSub)
	}

	// 4. Test IpfsGet with scan token escaping
	_ = IpfsGet("cid/123", srv.URL, tempDir, "token&admin=true")
	lastPath = requestedRawPaths[len(requestedRawPaths)-1]
	wantSub = "/api/v1/ipfs/objects/cid%2F123"
	if lastPath != wantSub {
		t.Errorf("IpfsGet path = %q, want %q", lastPath, wantSub)
	}
	lastQuery := requestedRawQueries[len(requestedRawQueries)-1]
	if lastQuery != "scan=token%26admin%3Dtrue" {
		t.Errorf("IpfsGet query = %q, want %q", lastQuery, "scan=token%26admin%3Dtrue")
	}
}
