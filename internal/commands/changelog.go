package commands

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// Changelog displays the unified activity timeline for a repository.
func Changelog(repoInput string, limit int, nodeURL, dirOverride string) error {
	if repoInput == "" {
		if o, r, ok := DetectGitRemote(); ok {
			repoInput = fmt.Sprintf("%s/%s", o, r)
		}
	}

	if repoInput == "" {
		return errors.New("no repo specified — pass <repo> or run from inside a Twigpine repo")
	}

	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	if limit <= 0 {
		limit = 20
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	endpoint := fmt.Sprintf("/api/v1/repos/%s/%s/changelog?limit=%d", url.PathEscape(owner), url.PathEscape(name), limit)
	resp, err := c.GetAuthed(endpoint)
	if err != nil {
		return fmt.Errorf("fetching changelog: %w", err)
	}

	return PrintResponseOrError(resp)
}
