package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
)

// Whoami prints current identity and node registration details.
func Whoami(nodeURL, dirOverride string, outputJSON bool) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	d := kp.DID()
	short := did.ShortDID(d)

	var registered *bool
	var trustScore *float64
	var capabilities []string
	var repoCount *int

	if nodeURL != "" {
		nodeURL = client.ResolveNodeURL(nodeURL)
		c := client.New(nodeURL, kp)

		resp, err := c.Get(fmt.Sprintf("/api/v1/agents/%s", url.PathEscape(d)))
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				regTrue := true
				registered = &regTrue

				var info map[string]interface{}
				_ = json.NewDecoder(resp.Body).Decode(&info)
				if ts, ok := info["trust_score"].(float64); ok {
					trustScore = &ts
				}
				if caps, ok := info["capabilities"].([]interface{}); ok {
					for _, c := range caps {
						if s, ok := c.(string); ok {
							capabilities = append(capabilities, s)
						}
					}
				}

				// Check repo count
				if reposResp, err := c.Get(fmt.Sprintf("/api/v1/repos?owner=%s", url.QueryEscape(short))); err == nil {
					defer reposResp.Body.Close()
					if reposResp.StatusCode == http.StatusOK {
						var repos []interface{}
						if json.NewDecoder(reposResp.Body).Decode(&repos) == nil {
							cnt := len(repos)
							repoCount = &cnt
						}
					}
				}
			} else if resp.StatusCode == http.StatusNotFound {
				regFalse := false
				registered = &regFalse
			} else {
				data, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("agent lookup failed (%d): %s", resp.StatusCode, client.SanitizeNodeMsg(string(data)))
			}
		}
	}

	if outputJSON {
		out := map[string]interface{}{
			"did":   d,
			"short": short,
		}
		if registered != nil {
			out["registered"] = *registered
		}
		if trustScore != nil {
			out["trust_score"] = *trustScore
		}
		if len(capabilities) > 0 {
			out["capabilities"] = capabilities
		}
		if repoCount != nil {
			out["repos"] = *repoCount
		}
		return PrintJSON(out)
	}

	fmt.Printf("DID:        %s\n", d)
	fmt.Printf("Short:      %s\n", short)
	if registered != nil {
		statusStr := "no"
		if *registered {
			statusStr = "yes"
		}
		fmt.Printf("Registered: %s\n", statusStr)
	}
	if trustScore != nil {
		fmt.Printf("Trust:      %.2f\n", *trustScore)
	}
	if len(capabilities) > 0 {
		fmt.Printf("Caps:       %s\n", strings.Join(capabilities, ", "))
	}
	if repoCount != nil {
		fmt.Printf("Repos:      %d\n", *repoCount)
	}

	return nil
}
