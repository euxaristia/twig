package commands

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/Twigpine/twig/internal/client"
)

func testGitRepo(t *testing.T, originURL string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("remote", "add", "origin", originURL)
	// Simulate fetched state: a local commit tracked by refs/remotes/origin/main.
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("commit", "--allow-empty", "-m", "init")
	run("update-ref", "refs/remotes/origin/main", "HEAD")
	return dir
}

func testIdentityDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := IdentityNew(dir, false, strings.NewReader("")); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}
	return dir
}

func testNodeServer(registerStatus int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/register" && r.Method == http.MethodPost:
			if registerStatus != http.StatusOK {
				w.WriteHeader(registerStatus)
				_, _ = w.Write([]byte(`{"message":"registration exploded"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"Welcome","ucan":"","trust_score":0.9,"expires":"2027-01-01"}`))
		case r.URL.Path == "/api/v1/repos" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"myrepo"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func gitConfig(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v failed: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// TestInitPreservesOriginRemote verifies init never removes or rewrites the
// existing origin remote and adds its own remote under a separate name.
func TestInitPreservesOriginRemote(t *testing.T) {
	const originURL = "https://example.com/owner/repo.git"
	workdir := testGitRepo(t, originURL)
	fetchCfg := gitConfig(t, workdir, "config", "--get", "remote.origin.fetch")

	srv := testNodeServer(http.StatusOK)
	defer srv.Close()
	idDir := testIdentityDir(t)

	t.Chdir(workdir)
	if err := Init("myrepo", "desc", srv.URL, idDir); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if got := gitConfig(t, workdir, "remote", "get-url", "origin"); got != originURL {
		t.Fatalf("origin URL changed: %q != %q", got, originURL)
	}
	if got := gitConfig(t, workdir, "config", "--get", "remote.origin.fetch"); got != fetchCfg {
		t.Fatalf("origin fetch config changed: %q != %q", got, fetchCfg)
	}
	if got := gitConfig(t, workdir, "rev-parse", "refs/remotes/origin/main"); got == "" {
		t.Fatalf("remote-tracking ref refs/remotes/origin/main was removed")
	}

	remoteName := client.GitURLScheme()
	gotURL := gitConfig(t, workdir, "remote", "get-url", remoteName)
	if !strings.HasPrefix(gotURL, client.GitURLScheme()+"://") || !strings.HasSuffix(gotURL, "/myrepo") {
		t.Fatalf("unexpected %s remote URL: %q", remoteName, gotURL)
	}
}

// TestInitFailsFastOnRegistrationError verifies setup failures propagate
// before any git remote is touched.
func TestInitFailsFastOnRegistrationError(t *testing.T) {
	const originURL = "https://example.com/owner/repo.git"
	workdir := testGitRepo(t, originURL)

	srv := testNodeServer(http.StatusInternalServerError)
	defer srv.Close()
	idDir := testIdentityDir(t)

	t.Chdir(workdir)
	err := Init("myrepo", "desc", srv.URL, idDir)
	if err == nil {
		t.Fatalf("expected Init to fail on registration error")
	}
	if !strings.Contains(err.Error(), "registration failed") {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := gitConfig(t, workdir, "remote", "get-url", "origin"); got != originURL {
		t.Fatalf("origin URL changed after failed init: %q", got)
	}
	remotes := gitConfig(t, workdir, "remote")
	if strings.Contains(remotes, "twigpine") || strings.Contains(remotes, "gitlawb") {
		t.Fatalf("new remote added despite failed init: %q", remotes)
	}
}
