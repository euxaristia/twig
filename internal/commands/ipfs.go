package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// IpfsList lists all CIDs pinned to the node's IPFS daemon.
func IpfsList(nodeURL, dirOverride string) error {
	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed("/api/v1/ipfs/pins")
	if err != nil {
		return fmt.Errorf("listing IPFS pins: %w", err)
	}

	return PrintResponseOrError(resp)
}

// IpfsGet retrieves a git object from the node by CIDv1.
func IpfsGet(cid, nodeURL, dirOverride, scanToken string) error {
	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	path := fmt.Sprintf("/api/v1/ipfs/objects/%s", url.PathEscape(cid))
	if scanToken != "" {
		path += "?scan=" + url.QueryEscape(scanToken)
	}

	resp, err := c.GetAuthed(path)
	if err != nil {
		return fmt.Errorf("retrieving IPFS object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		_, err := io.Copy(os.Stdout, resp.Body)
		return err
	}

	if resp.StatusCode == http.StatusServiceUnavailable {
		var errData map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		if resumeToken, ok := errData["resume_token"].(string); ok && resumeToken != "" {
			fmt.Fprintf(os.Stderr, "Scan incomplete. Resume with:\n  twig ipfs get %s --scan %s\n", cid, resumeToken)
			os.Exit(2)
		}
	}

	data, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("IPFS get failed (%d): %s", resp.StatusCode, client.SanitizeNodeMsg(string(data)))
}
