package commands

import (
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// StarAdd stars a repository.
func StarAdd(repoInput, nodeURL, dirOverride string) error {
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

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/star", url.PathEscape(owner), url.PathEscape(name)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("starring repo: %w", err)
	}

	return PrintResponseOrError(resp)
}

// StarRemove unstars a repository.
func StarRemove(repoInput, nodeURL, dirOverride string) error {
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

	resp, err := c.Delete(fmt.Sprintf("/api/v1/repos/%s/%s/star", url.PathEscape(owner), url.PathEscape(name)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("unstarring repo: %w", err)
	}

	return PrintResponseOrError(resp)
}

// StarCount prints the star count for a repository.
func StarCount(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/stars", url.PathEscape(owner), url.PathEscape(name)))
	if err != nil {
		return fmt.Errorf("fetching stars: %w", err)
	}

	return PrintResponseOrError(resp)
}
