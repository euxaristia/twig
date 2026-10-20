package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// PrCreate opens a pull request.
func PrCreate(repoInput, head, base, title, body, ownerOverride, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}
	if ownerOverride != "" {
		owner = ownerOverride
	}

	if base == "" {
		base = "main"
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"title":         title,
		"source_branch": head,
		"target_branch": base,
		"body":          body,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(name)), bodyBytes)
	if err != nil {
		return fmt.Errorf("creating PR: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PrList lists pull requests for a repository.
func PrList(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(name)))
	if err != nil {
		return fmt.Errorf("listing PRs: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PrView shows details of a pull request.
func PrView(repoInput string, number int, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d", url.PathEscape(owner), url.PathEscape(name), number))
	if err != nil {
		return fmt.Errorf("fetching PR: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PrDiff shows the diff of a pull request.
func PrDiff(repoInput string, number int, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/diff", url.PathEscape(owner), url.PathEscape(name), number))
	if err != nil {
		return fmt.Errorf("fetching PR diff: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

// PrMerge merges a pull request.
func PrMerge(repoInput string, number int, nodeURL, dirOverride string) error {
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

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/merge", url.PathEscape(owner), url.PathEscape(name), number), []byte("{}"))
	if err != nil {
		return fmt.Errorf("merging PR: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PrReview submits a review on a pull request.
func PrReview(repoInput string, number int, status, body, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	if status == "" {
		status = "comment"
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"status": status,
		"body":   body,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/reviews", url.PathEscape(owner), url.PathEscape(name), number), bodyBytes)
	if err != nil {
		return fmt.Errorf("submitting review: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PrComment adds a comment on a pull request.
func PrComment(repoInput string, number int, body, nodeURL, dirOverride string) error {
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

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/comments", url.PathEscape(owner), url.PathEscape(name), number), bodyBytes)
	if err != nil {
		return fmt.Errorf("commenting on PR: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PrComments lists comments on a pull request.
func PrComments(repoInput string, number int, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/pulls/%d/comments", url.PathEscape(owner), url.PathEscape(name), number))
	if err != nil {
		return fmt.Errorf("fetching PR comments: %w", err)
	}

	return PrintResponseOrError(resp)
}
