package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Twigpine/twig/internal/client"
)

// WebhookCreate creates a webhook for a repository.
func WebhookCreate(repoInput, webhookURL, events, secret, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	if events == "" {
		events = "*"
	}

	eventList := strings.Split(events, ",")
	for i := range eventList {
		eventList[i] = strings.TrimSpace(eventList[i])
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"url":    webhookURL,
		"events": eventList,
		"secret": secret,
	})

	resp, err := c.Post(fmt.Sprintf("/api/v1/repos/%s/%s/webhooks", url.PathEscape(owner), url.PathEscape(name)), bodyBytes)
	if err != nil {
		return fmt.Errorf("creating webhook: %w", err)
	}

	return PrintResponseOrError(resp)
}

// WebhookList lists webhooks for a repository.
func WebhookList(repoInput, nodeURL, dirOverride string) error {
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

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/webhooks", url.PathEscape(owner), url.PathEscape(name)))
	if err != nil {
		return fmt.Errorf("listing webhooks: %w", err)
	}

	return PrintResponseOrError(resp)
}

// WebhookDelete deletes a webhook from a repository.
func WebhookDelete(repoInput, webhookID, nodeURL, dirOverride string) error {
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

	resp, err := c.Delete(fmt.Sprintf("/api/v1/repos/%s/%s/webhooks/%s", url.PathEscape(owner), url.PathEscape(name), url.PathEscape(webhookID)), []byte("{}"))
	if err != nil {
		return fmt.Errorf("deleting webhook: %w", err)
	}

	return PrintResponseOrError(resp)
}
