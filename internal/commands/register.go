package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/identity"
)

// Register registers the local agent identity with a Twigpine node.
func Register(nodeURL string, capabilities []string, model, dirOverride string) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	if len(capabilities) == 0 {
		capabilities = []string{"git:push", "git:fetch", "issue:create", "pr:open"}
	}

	nodeURL = client.ResolveNodeURL(nodeURL)
	d := kp.DID()

	fmt.Printf("Registering agent with %s...\n", nodeURL)
	fmt.Printf("  DID:          %s\n", d)
	fmt.Printf("  Capabilities: %s\n", strings.Join(capabilities, ", "))

	c := client.New(nodeURL, kp)

	bodyData := map[string]interface{}{
		"did":          d,
		"capabilities": capabilities,
	}
	if model != "" {
		bodyData["model"] = model
	}

	bodyBytes, err := json.Marshal(bodyData)
	if err != nil {
		return err
	}

	resp, err := c.Post("/api/register", bodyBytes)
	if err != nil {
		return fmt.Errorf("failed to connect to node: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var payload map[string]interface{}
	_ = json.Unmarshal(respBytes, &payload)

	if resp.StatusCode >= 400 {
		msg := "unknown error"
		if m, ok := payload["message"].(string); ok && m != "" {
			msg = m
		}
		return fmt.Errorf("registration failed (%d): %s", resp.StatusCode, client.SanitizeNodeMsg(msg))
	}

	// Save bootstrap UCAN
	if ucanToken, ok := payload["ucan"].(string); ok && ucanToken != "" {
		dir, _ := identity.DefaultDir(dirOverride)
		_ = os.MkdirAll(dir, 0700)
		ucanPath := filepath.Join(dir, "ucan.json")
		record := map[string]interface{}{
			"ucan":     ucanToken,
			"node":     nodeURL,
			"did":      d,
			"saved_at": time.Now().Format(time.RFC3339),
		}
		recordBytes, _ := json.MarshalIndent(record, "", "  ")
		_ = os.WriteFile(ucanPath, recordBytes, 0600)
		_ = os.Chmod(ucanPath, 0600)
	}

	trustScore := 0.0
	if ts, ok := payload["trust_score"].(float64); ok {
		trustScore = ts
	}

	expires := "unknown"
	if exp, ok := payload["expires"].(string); ok {
		expires = exp
	}

	message := ""
	if msg, ok := payload["message"].(string); ok {
		message = msg
	}

	fmt.Println()
	if message != "" {
		fmt.Printf("  %s\n", message)
	}
	fmt.Printf("  Trust score:  %.2f\n", trustScore)
	fmt.Printf("  UCAN expires: %s\n\n", expires)
	fmt.Println("  Bootstrap UCAN saved to ~/.twigpine/ucan.json")
	fmt.Println("  You are now a verified agent on the Twigpine network.")

	return nil
}
