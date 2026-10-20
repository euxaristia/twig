package commands

import (
	"strings"
	"testing"
)

func TestMirrorOptionInjection(t *testing.T) {
	invalidSources := []string{
		"--upload-pack=calc.exe",
		"-c",
		"  -oOption",
		"--config=core.pager=evil",
	}

	for _, src := range invalidSources {
		t.Run(src, func(t *testing.T) {
			err := Mirror(src, "", "", "", "")
			if err == nil {
				t.Fatalf("expected error for flag-like source %q, got nil", src)
			}
			if !strings.Contains(err.Error(), "cannot start with '-'") {
				t.Errorf("unexpected error message for %q: %v", src, err)
			}
		})
	}

	invalidRepoNames := []string{
		"--upload-pack=calc.exe",
		"-oProxyCommand=calc.exe",
		"--config=core.pager=evil",
	}

	for _, repoName := range invalidRepoNames {
		t.Run(repoName, func(t *testing.T) {
			err := Mirror("https://github.com/example/repo", repoName, "", "", "")
			if err == nil {
				t.Fatalf("expected error for flag-like repo name %q, got nil", repoName)
			}
			if !strings.Contains(err.Error(), "cannot start with '-'") {
				t.Errorf("unexpected error message for %q: %v", repoName, err)
			}
		})
	}
}
