package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
)

// PrintJSON pretty-prints a value as JSON to stdout.
func PrintJSON(v interface{}) error {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(bytes))
	return nil
}

// PrintResponseOrError prints the formatted response body or an actionable error message.
func PrintResponseOrError(resp *http.Response) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errObj map[string]interface{}
		if json.Unmarshal(data, &errObj) == nil {
			if msg, ok := errObj["message"].(string); ok && msg != "" {
				return fmt.Errorf("request failed (%d): %s", resp.StatusCode, client.SanitizeNodeMsg(msg))
			}
			if msg, ok := errObj["error"].(string); ok && msg != "" {
				return fmt.Errorf("request failed (%d): %s", resp.StatusCode, client.SanitizeNodeMsg(msg))
			}
		}
		rawMsg := client.SanitizeNodeMsg(string(data))
		if rawMsg == "" {
			rawMsg = resp.Status
		}
		return fmt.Errorf("request failed (%d): %s", resp.StatusCode, rawMsg)
	}

	var parsed interface{}
	if json.Unmarshal(data, &parsed) == nil {
		pretty, err := json.MarshalIndent(parsed, "", "  ")
		if err == nil {
			fmt.Println(string(pretty))
			return nil
		}
	}

	fmt.Println(string(data))
	return nil
}

// ResolveRepoOwner extracts the owner and repo name.
// If repo is in "owner/name" form, it is split.
// Otherwise, it attempts to load local keypair's short DID as owner.
func ResolveRepoOwner(repoInput, dir string) (string, string, error) {
	repoInput = strings.TrimSpace(repoInput)
	if strings.HasPrefix(repoInput, "twigpine://") {
		repoInput = strings.TrimPrefix(repoInput, "twigpine://")
	} else if strings.HasPrefix(repoInput, "gitlawb://") {
		repoInput = strings.TrimPrefix(repoInput, "gitlawb://")
	}
	repoInput = strings.TrimRight(repoInput, "/")

	var owner, repo string
	if strings.Contains(repoInput, "/") {
		parts := strings.SplitN(repoInput, "/", 2)
		owner, repo = parts[0], parts[1]
	} else {
		// Try loading identity
		kp, err := identity.LoadKeypair(dir)
		if err != nil {
			return "", "", fmt.Errorf("repo must be in owner/name format, or an identity must exist: %s", repoInput)
		}
		owner, repo = did.ShortDID(kp.DID()), repoInput
	}

	if strings.HasPrefix(owner, "-") || strings.HasPrefix(repo, "-") {
		return "", "", fmt.Errorf("invalid repository input %q: owner and repo name cannot start with '-'", repoInput)
	}

	return owner, repo, nil
}

// DetectGitRemote attempts to detect a twigpine:// or gitlawb:// remote from current git directory.
func DetectGitRemote() (string, string, bool) {
	out, err := exec.Command("git", "remote", "-v").Output()
	if err != nil {
		return "", "", false
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			remoteURL := fields[1]
			if strings.HasPrefix(remoteURL, "twigpine://") || strings.HasPrefix(remoteURL, "gitlawb://") {
				stripped := remoteURL
				if strings.HasPrefix(stripped, "twigpine://") {
					stripped = strings.TrimPrefix(stripped, "twigpine://")
				} else {
					stripped = strings.TrimPrefix(stripped, "gitlawb://")
				}
				stripped = strings.TrimSuffix(stripped, ".git")
				parts := strings.SplitN(stripped, "/", 2)
				if len(parts) == 2 {
					return parts[0], parts[1], true
				}
			}
		}
	}
	return "", "", false
}

// EnsureIdentityExists loads the keypair or returns a user-friendly error.
func EnsureIdentityExists(dir string) (*identity.Keypair, error) {
	kp, err := identity.LoadKeypair(dir)
	if err != nil {
		return nil, errors.New("identity not found — run `twig identity new` first")
	}
	return kp, nil
}
