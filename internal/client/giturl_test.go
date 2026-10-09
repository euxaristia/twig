package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// helperFileName returns the file name a fake remote helper must have for
// exec.LookPath to resolve it on the current platform. On Windows LookPath
// only resolves names through PATHEXT, so an extensionless stub is invisible
// and the stub must be written with a .exe suffix. The stub is never
// executed (LookPath only stats the file), so its shell content is
// irrelevant on every platform.
func helperFileName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func writeFakeHelper(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, helperFileName(name)), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("writing fake helper: %v", err)
	}
}

// TestGitURLSchemeMatchesInstalledHelper verifies generated URLs use the
// transport of the helper actually on PATH.
func TestGitURLSchemeMatchesInstalledHelper(t *testing.T) {
	dir := t.TempDir()
	writeFakeHelper(t, dir, "git-remote-gitlawb")
	t.Setenv("PATH", dir)

	if got := GitURLScheme(); got != "gitlawb" {
		t.Fatalf("GitURLScheme() = %q, want gitlawb", got)
	}
	if got := FormatGitURL("owner", "repo"); got != "gitlawb://owner/repo" {
		t.Fatalf("FormatGitURL() = %q, want gitlawb://owner/repo", got)
	}
}

// TestGitURLSchemePrefersTwigpine verifies the new helper wins when both are
// installed.
func TestGitURLSchemePrefersTwigpine(t *testing.T) {
	dir := t.TempDir()
	writeFakeHelper(t, dir, "git-remote-gitlawb")
	writeFakeHelper(t, dir, "git-remote-twigpine")
	t.Setenv("PATH", dir)

	if got := GitURLScheme(); got != "twigpine" {
		t.Fatalf("GitURLScheme() = %q, want twigpine", got)
	}
	if got := FormatGitURL("owner", "repo"); got != "twigpine://owner/repo" {
		t.Fatalf("FormatGitURL() = %q, want twigpine://owner/repo", got)
	}
}
