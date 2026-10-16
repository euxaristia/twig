package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// BountyCreate creates a bounty on an issue.
func BountyCreate(repoInput, title string, amount int64, issueID, txHash string, deadline int64, nodeURL, dirOverride string) error {
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

	body := map[string]interface{}{
		"title":  title,
		"amount": amount,
	}
	if issueID != "" {
		body["issue_id"] = issueID
	}
	if txHash != "" {
		body["tx_hash"] = txHash
	}
	if deadline > 0 {
		body["deadline"] = deadline
	}

	bodyBytes, _ := json.Marshal(body)
	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/bounties", url.PathEscape(owner), url.PathEscape(name)), bodyBytes)
	if err != nil {
		return fmt.Errorf("creating bounty: %w", err)
	}

	return PrintResponseOrError(resp)
}

// BountyList lists bounties on the network or repo.
func BountyList(repoInput, status, nodeURL, dirOverride string) error {
	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	endpoint := "/api/v1/bounties"
	q := url.Values{}
	if repoInput != "" {
		q.Set("repo", repoInput)
	}
	if status != "" {
		q.Set("status", status)
	}
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}

	resp, err := c.GetAuthed(endpoint)
	if err != nil {
		return fmt.Errorf("listing bounties: %w", err)
	}

	return PrintResponseOrError(resp)
}

// BountyShow shows details of a specific bounty.
func BountyShow(bountyID, nodeURL, dirOverride string) error {
	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/bounties/%s", url.PathEscape(bountyID)))
	if err != nil {
		return fmt.Errorf("fetching bounty: %w", err)
	}

	return PrintResponseOrError(resp)
}

// BountyClaim claims an open bounty.
func BountyClaim(bountyID, wallet, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"wallet": wallet,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/bounties/%s/claim", url.PathEscape(bountyID)), bodyBytes)
	if err != nil {
		return fmt.Errorf("claiming bounty: %w", err)
	}

	return PrintResponseOrError(resp)
}

// BountySubmit submits a PR for bounty review.
func BountySubmit(bountyID, prID, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"pr_id": prID,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/bounties/%s/submit", url.PathEscape(bountyID)), bodyBytes)
	if err != nil {
		return fmt.Errorf("submitting bounty work: %w", err)
	}

	return PrintResponseOrError(resp)
}

// BountyApprove approves a submitted bounty.
func BountyApprove(bountyID, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.Post(fmt.Sprintf("/api/v1/bounties/%s/approve", url.PathEscape(bountyID)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("approving bounty: %w", err)
	}

	return PrintResponseOrError(resp)
}

// BountyCancel cancels an active bounty.
func BountyCancel(bountyID, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.Post(fmt.Sprintf("/api/v1/bounties/%s/cancel", url.PathEscape(bountyID)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("cancelling bounty: %w", err)
	}

	return PrintResponseOrError(resp)
}
