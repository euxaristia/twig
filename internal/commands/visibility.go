package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
)

// VisibilitySet sets a path-scoped visibility rule on a repository.
func VisibilitySet(pathGlob, repoInput string, readers []string, mode, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	if mode == "" {
		mode = "b"
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"path_glob": pathGlob,
		"readers":   readers,
		"mode":      mode,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/visibility", url.PathEscape(owner), url.PathEscape(name)), bodyBytes)
	if err != nil {
		return fmt.Errorf("setting visibility rule: %w", err)
	}

	return PrintResponseOrError(resp)
}

// VisibilityRemove removes a path-scoped visibility rule from a repository.
func VisibilityRemove(pathGlob, repoInput, nodeURL, dirOverride string) error {
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

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"path_glob": pathGlob,
	})

	resp, err := c.Delete(fmt.Sprintf("/api/v1/repos/%s/%s/visibility", url.PathEscape(owner), url.PathEscape(name)), bodyBytes)
	if err != nil {
		return fmt.Errorf("removing visibility rule: %w", err)
	}

	return PrintResponseOrError(resp)
}

// VisibilityList lists visibility rules for a repository.
func VisibilityList(repoInput, nodeURL, dirOverride string) error {
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

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/visibility", url.PathEscape(owner), url.PathEscape(name)))
	if err != nil {
		return fmt.Errorf("listing visibility rules: %w", err)
	}

	return PrintResponseOrError(resp)
}
