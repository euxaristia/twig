package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
)

// TrustBar renders an ASCII trust bar: 0.75 -> "███░".
func TrustBar(score float64) string {
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	filled := int((score * 4.0) + 0.5)
	if filled > 4 {
		filled = 4
	}
	empty := 4 - filled
	return strings.Repeat("█", filled) + strings.Repeat("░", empty)
}

// ParseTwigpineURL parses a twigpine:// or gitlawb:// URL string into (did, repo, true).
func ParseTwigpineURL(url string) (string, string, bool) {
	url = strings.TrimSpace(url)
	var rest string
	if strings.HasPrefix(url, "twigpine://") {
		rest = strings.TrimPrefix(url, "twigpine://")
	} else if strings.HasPrefix(url, "gitlawb://") {
		rest = strings.TrimPrefix(url, "gitlawb://")
	} else {
		return "", "", false
	}
	slash := strings.LastIndex(rest, "/")
	if slash == -1 {
		return "", "", false
	}
	didPart := rest[:slash]
	repo := rest[slash+1:]
	if didPart == "" || repo == "" {
		return "", "", false
	}
	return didPart, repo, true
}

// Status prints a snapshot of identity, node, and repo context.
func Status(nodeURL, dirOverride string) error {
	nodeURL = client.ResolveNodeURL(nodeURL)
	kp, _ := identity.LoadKeypair(dirOverride)
	c := client.New(nodeURL, kp)

	// Identity
	if kp != nil {
		d := kp.DID()
		short := d
		if len(short) > 40 {
			short = short[:40] + "…"
		}
		fmt.Printf("  identity  %s\n", short)

		// Trust
		if resp, err := c.Get(fmt.Sprintf("/api/v1/agents/%s", url.PathEscape(did.ShortDID(d)))); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var info map[string]interface{}
				_ = json.NewDecoder(resp.Body).Decode(&info)
				score, _ := info["trust_score"].(float64)
				fmt.Printf("  trust     %.2f  %s\n", score, TrustBar(score))
			} else {
				fmt.Println("  trust     — not registered (run `twig register`)")
			}
		}
	} else {
		fmt.Println("  identity  ✗ not found — run `twig identity new`")
	}

	// Git repo context
	if owner, repo, ok := DetectGitRemote(); ok {
		fmt.Printf("  repo      %s/%s\n", owner, repo)

		// Open PRs
		if resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(repo))); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var prs []interface{}
				if json.NewDecoder(resp.Body).Decode(&prs) == nil {
					fmt.Printf("  open PRs  %d\n", len(prs))
				}
			}
		}

		// Open issues
		if resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/issues", url.PathEscape(owner), url.PathEscape(repo))); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var issues []interface{}
				if json.NewDecoder(resp.Body).Decode(&issues) == nil {
					fmt.Printf("  issues    %d\n", len(issues))
				}
			}
		}
	} else {
		fmt.Println("  repo      (not inside a Twigpine repo)")
	}

	return nil
}
