package commands

import (
	"fmt"
	"net/url"

	"github.com/Twigpine/twig/internal/client"
)

// AgentList lists registered agents on the node.
func AgentList(capability, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	path := "/api/v1/agents"
	if capability != "" {
		path += "?capability=" + url.QueryEscape(capability)
	}

	resp, err := c.Get(path)
	if err != nil {
		return fmt.Errorf("listing agents: %w", err)
	}

	return PrintResponseOrError(resp)
}

// AgentShow displays details for a specific agent DID.
func AgentShow(targetDID, nodeURL string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, nil)

	resp, err := c.Get(fmt.Sprintf("/api/v1/agents/%s", url.PathEscape(targetDID)))
	if err != nil {
		return fmt.Errorf("fetching agent: %w", err)
	}

	return PrintResponseOrError(resp)
}
