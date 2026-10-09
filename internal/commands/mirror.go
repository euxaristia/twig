package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
)

// Mirror mirrors a public Git repository into Twigpine.
func Mirror(source, repoNameOverride, description, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	source = strings.TrimRight(source, "/")
	repoName := repoNameOverride
	if repoName == "" {
		base := path.Base(source)
		repoName = strings.TrimSuffix(base, ".git")
	}

	if repoName == "" {
		return fmt.Errorf("could not derive repo name from %s — use --repo", source)
	}

	tempDir, err := os.MkdirTemp("", "twig-mirror-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	fmt.Printf("Cloning %s into temporary mirror...\n", source)
	cloneCmd := exec.Command("git", "clone", "--mirror", source, tempDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone --mirror failed: %w", err)
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	owner := did.ShortDID(kp.DID())

	fmt.Printf("Creating repository %s on %s...\n", repoName, nodeURL)
	_ = RepoCreate(repoName, description, false, "main", nodeURL, dirOverride)

	remoteURL := client.FormatGitURL(owner, repoName)
	fmt.Printf("Pushing mirror to %s...\n", remoteURL)
	pushCmd := exec.Command("git", "push", "--mirror", remoteURL)
	pushCmd.Dir = tempDir
	pushCmd.Stdout = os.Stdout
	pushCmd.Stderr = os.Stderr
	if err := pushCmd.Run(); err != nil {
		return fmt.Errorf("git push --mirror failed: %w", err)
	}

	fmt.Printf("✓ Repository successfully mirrored to %s\n", remoteURL)
	return nil
}
