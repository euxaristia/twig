package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// IssueCreate creates a new issue in a repository.
func IssueCreate(repoInput, title, body, nodeURL, dirOverride string) error {
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
		"title": title,
		"body":  body,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/issues", url.PathEscape(owner), url.PathEscape(name)), bodyBytes)
	if err != nil {
		return fmt.Errorf("creating issue: %w", err)
	}

	return PrintResponseOrError(resp)
}

// IssueList lists issues in a repository.
func IssueList(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/issues", url.PathEscape(owner), url.PathEscape(name)))
	if err != nil {
		return fmt.Errorf("listing issues: %w", err)
	}

	return PrintResponseOrError(resp)
}

// IssueShow shows a specific issue in a repository.
func IssueShow(repoInput, issueID, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/issues/%s", url.PathEscape(owner), url.PathEscape(name), url.PathEscape(issueID)))
	if err != nil {
		return fmt.Errorf("fetching issue: %w", err)
	}

	return PrintResponseOrError(resp)
}

// IssueClose closes an issue.
func IssueClose(repoInput, issueID, nodeURL, dirOverride string) error {
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

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/issues/%s/close", url.PathEscape(owner), url.PathEscape(name), url.PathEscape(issueID)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("closing issue: %w", err)
	}

	return PrintResponseOrError(resp)
}

// IssueComment adds a comment to an issue.
func IssueComment(repoInput, issueID, body, nodeURL, dirOverride string) error {
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
		"body": body,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/issues/%s/comments", url.PathEscape(owner), url.PathEscape(name), url.PathEscape(issueID)), bodyBytes)
	if err != nil {
		return fmt.Errorf("commenting on issue: %w", err)
	}

	return PrintResponseOrError(resp)
}

// IssueComments lists comments on an issue.
func IssueComments(repoInput, issueID, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/issues/%s/comments", url.PathEscape(owner), url.PathEscape(name), url.PathEscape(issueID)))
	if err != nil {
		return fmt.Errorf("fetching comments: %w", err)
	}

	return PrintResponseOrError(resp)
}
