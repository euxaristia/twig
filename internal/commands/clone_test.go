package commands

import (
	"strings"
	"testing"
)

func TestCloneOptionInjection(t *testing.T) {
	t.Run("invalid destDir", func(t *testing.T) {
		err := Clone("owner/repo", "--upload-pack=evil", "", "", "", "")
		if err == nil {
			t.Fatal("expected error for flag-like destDir, got nil")
		}
		if !strings.Contains(err.Error(), "cannot start with '-'") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("invalid branch", func(t *testing.T) {
		err := Clone("owner/repo", "my-repo", "--config=core.pager=evil", "", "", "")
		if err == nil {
			t.Fatal("expected error for flag-like branch, got nil")
		}
		if !strings.Contains(err.Error(), "cannot start with '-'") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}
