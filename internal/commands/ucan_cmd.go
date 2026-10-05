package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Twigpine/twig/internal/identity"
	"github.com/Twigpine/twig/internal/ucan"
)

// UcanDelegate delegates capabilities to another agent and outputs or saves the UCAN.
func UcanDelegate(toDID, resource, action string, expiryHours int, outPath, dirOverride string, outputJSON bool) error {
	kp, err := EnsureIdentityExists(dirOverride)
	if err != nil {
		return err
	}

	var exp *time.Time
	if expiryHours > 0 {
		t := time.Now().Add(time.Duration(expiryHours) * time.Hour)
		exp = &t
	}

	token, err := ucan.Issue(kp, toDID, []ucan.Capability{
		{With: resource, Can: action},
	}, exp)
	if err != nil {
		return fmt.Errorf("issuing UCAN: %w", err)
	}

	encoded, err := token.Encode()
	if err != nil {
		return err
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(encoded), 0644); err != nil {
			return fmt.Errorf("writing UCAN file: %w", err)
		}
		fmt.Printf("✓ UCAN token saved to %s\n", outPath)
		return nil
	}

	if outputJSON {
		fmt.Println(encoded)
		return nil
	}

	fmt.Println(encoded)
	return nil
}

// UcanShow displays the saved bootstrap UCAN token.
func UcanShow(dirOverride string) error {
	dir, err := identity.DefaultDir(dirOverride)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "ucan.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no UCAN found at %s — run `twig register` first", path)
	}

	fmt.Println(string(data))
	return nil
}

// UcanVerify verifies a UCAN token string or token file.
func UcanVerify(tokenInput string) error {
	token, err := ucan.Decode(tokenInput)
	if err != nil {
		return fmt.Errorf("decoding UCAN: %w", err)
	}

	sigErr := token.VerifySignature()
	isExp := token.IsExpired()
	isNbf := token.IsBeforeValid()
	valid := (sigErr == nil && !isExp && !isNbf)

	out := map[string]interface{}{
		"valid":           valid,
		"signature_valid": sigErr == nil,
		"expired":         isExp,
		"not_before":      isNbf,
		"issuer":          token.Payload.Iss,
		"audience":        token.Payload.Aud,
		"capabilities":    token.Payload.Att,
		"expires":         token.Payload.Exp,
	}

	bytes, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(bytes))

	if !valid {
		if sigErr != nil {
			return fmt.Errorf("signature verification failed: %w", sigErr)
		}
		if isExp {
			return fmt.Errorf("UCAN token has expired")
		}
		if isNbf {
			return fmt.Errorf("UCAN token is not yet valid (nbf in future)")
		}
	}

	return nil
}
