package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
)

// ProfileSet updates profile metadata for the agent.
func ProfileSet(name, bio, avatar, website, twitter, github, farcaster, telegram string, pin bool, nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	body := map[string]interface{}{}
	if name != "" {
		body["name"] = name
	}
	if bio != "" {
		body["bio"] = bio
	}
	if avatar != "" {
		body["avatar"] = avatar
	}
	if website != "" {
		body["website"] = website
	}
	if twitter != "" {
		body["twitter"] = twitter
	}
	if github != "" {
		body["github"] = github
	}
	if farcaster != "" {
		body["farcaster"] = farcaster
	}
	if telegram != "" {
		body["telegram"] = telegram
	}
	if pin {
		body["pin"] = true
	}

	bodyBytes, _ := json.Marshal(body)
	resp, err := c.Put(fmt.Sprintf("/api/v1/agents/%s/profile", url.PathEscape(kp.DID())), bodyBytes)
	if err != nil {
		return fmt.Errorf("updating profile: %w", err)
	}

	return PrintResponseOrError(resp)
}

// ProfileShow shows an agent profile.
func ProfileShow(targetDID, nodeURL, dirOverride string) error {
	if targetDID == "" {
		kp, err := EnsureIdentityExists(dirOverride)
		if err != nil {
			return err
		}
		targetDID = kp.DID()
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get(fmt.Sprintf("/api/v1/agents/%s/profile", url.PathEscape(targetDID)))
	if err != nil {
		return fmt.Errorf("fetching profile: %w", err)
	}

	return PrintResponseOrError(resp)
}

// ProfileClear clears profile metadata.
func ProfileClear(nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.Delete(fmt.Sprintf("/api/v1/agents/%s/profile", url.PathEscape(kp.DID())), []byte("{}"))
	if err != nil {
		return fmt.Errorf("clearing profile: %w", err)
	}

	return PrintResponseOrError(resp)
}

// ProfilePin pins profile to IPFS.
func ProfilePin(nodeURL, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.Post(fmt.Sprintf("/api/v1/agents/%s/profile/pin", url.PathEscape(kp.DID())), []byte("{}"))
	if err != nil {
		return fmt.Errorf("pinning profile: %w", err)
	}

	return PrintResponseOrError(resp)
}
