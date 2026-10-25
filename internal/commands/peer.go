package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
)

// PeerList lists known peers on the node.
func PeerList(nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get("/api/v1/peers")
	if err != nil {
		return fmt.Errorf("listing peers: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PeerAdd announces this node to a peer node.
func PeerAdd(peerURL, nodeURL, dirOverride string) error {
	if err := client.ValidateEndpointURL(peerURL); err != nil {
		return fmt.Errorf("invalid peer URL: %w", err)
	}

	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"peer_url": peerURL,
	})

	resp, err := c.Post("/api/v1/peers", bodyBytes)
	if err != nil {
		return fmt.Errorf("adding peer: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PeerPing pings a peer by DID.
func PeerPing(targetDID, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get(fmt.Sprintf("/api/v1/peers/%s/ping", url.PathEscape(targetDID)))
	if err != nil {
		return fmt.Errorf("pinging peer: %w", err)
	}

	return PrintResponseOrError(resp)
}

// PeerResolve resolves a DID to its peer node info.
func PeerResolve(targetDID, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get(fmt.Sprintf("/api/v1/peers/%s", url.PathEscape(targetDID)))
	if err != nil {
		return fmt.Errorf("resolving peer: %w", err)
	}

	return PrintResponseOrError(resp)
}
