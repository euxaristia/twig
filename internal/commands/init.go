package commands

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
)

// Init sets up a git repo and connects it with Twigpine in one step.
func Init(repoName, description, nodeURL, dirOverride string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	// 1. Ensure git repo exists
	gitDir := filepath.Join(cwd, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		fmt.Println("Initializing git repository...")
		cmd := exec.Command("git", "init", "-b", "main")
		if err := cmd.Run(); err != nil {
			// Older git fallback
			cmd2 := exec.Command("git", "init")
			if err := cmd2.Run(); err != nil {
				return fmt.Errorf("git init failed: %w", err)
			}
		}
	} else {
		fmt.Println("Git repository detected.")
	}

	// 2. Ensure identity exists
	kp, err := identity.LoadKeypair(dirOverride)
	if err != nil {
		fmt.Println("Creating new identity...")
		if err := IdentityNew(dirOverride, false, os.Stdin); err != nil {
			return err
		}
		kp, err = identity.LoadKeypair(dirOverride)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("Using existing identity: %s\n", kp.DID())
	}

	// 3. Register with node
	nodeURL = client.ResolveNodeURL(nodeURL)
	if err := Register(nodeURL, nil, "", dirOverride); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// 4. Derive repo name
	if repoName == "" {
		repoName = filepath.Base(cwd)
	}

	// 5. Create remote repo
	fmt.Printf("Creating repository %s on %s...\n", repoName, nodeURL)
	if err := RepoCreate(repoName, description, false, "main", nodeURL, dirOverride); err != nil {
		lower := strings.ToLower(err.Error())
		if !strings.Contains(lower, "exists") && !strings.Contains(lower, "already") {
			return fmt.Errorf("repository creation failed: %w", err)
		}
		fmt.Println("  Repository already exists — continuing.")
	}

	// 6. Add remote, preserving any existing remotes (never touch origin).
	owner := did.ShortDID(kp.DID())
	remoteURL := client.FormatGitURL(owner, repoName)
	remoteName := client.GitURLScheme()
	if out, err := exec.Command("git", "remote", "get-url", remoteName).Output(); err == nil && len(bytes.TrimSpace(out)) > 0 {
		fmt.Printf("  Remote '%s' already set.\n", remoteName)
	} else {
		if err := exec.Command("git", "remote", "add", remoteName, remoteURL).Run(); err != nil {
			return fmt.Errorf("adding git remote: %w", err)
		}
		fmt.Printf("  Remote added: %s\n", remoteURL)
	}

	fmt.Println("\n✓ Setup complete!")
	fmt.Printf("  Remote URL: %s\n\n", remoteURL)
	fmt.Println("To push your code:")
	fmt.Println("  git add .")
	fmt.Println("  git commit -m \"initial commit\"")
	fmt.Println("  git push -u origin main")

	return nil
}
