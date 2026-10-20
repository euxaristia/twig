package commands

import (
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// ProtectSet enables branch protection on a repository branch.
func ProtectSet(branch, repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	path := fmt.Sprintf("/api/v1/repos/%s/%s/branches/%s/protect", url.PathEscape(owner), url.PathEscape(name), url.PathEscape(branch))
	resp, err := c.Post(path, []byte("{}"))
	if err != nil {
		return fmt.Errorf("protecting branch: %w", err)
	}

	return PrintResponseOrError(resp)
}

// ProtectRemove removes branch protection from a repository branch.
func ProtectRemove(branch, repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	path := fmt.Sprintf("/api/v1/repos/%s/%s/branches/%s/protect", url.PathEscape(owner), url.PathEscape(name), url.PathEscape(branch))
	resp, err := c.Delete(path, []byte("{}"))
	if err != nil {
		return fmt.Errorf("removing branch protection: %w", err)
	}

	return PrintResponseOrError(resp)
}

// ProtectList lists protected branches for a repository.
func ProtectList(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	path := fmt.Sprintf("/api/v1/repos/%s/%s/branches/protected", url.PathEscape(owner), url.PathEscape(name))
	resp, err := c.GetAuthed(path)
	if err != nil {
		return fmt.Errorf("listing protected branches: %w", err)
	}

	return PrintResponseOrError(resp)
}
