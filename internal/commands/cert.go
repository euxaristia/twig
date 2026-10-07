package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Twigpine/twig/internal/client"
	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
)

// CertList lists ref certificates for a repository.
func CertList(repoInput, nodeURL, dirOverride string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/certs", owner, name))
	if err != nil {
		return fmt.Errorf("listing certs: %w", err)
	}

	return PrintResponseOrError(resp)
}

// certSignPayload mirrors the node's canonical signing payload
// (gitlawb-node/src/cert.rs::issue_ref_certificate). Fields are declared in
// alphabetical order because serde_json serializes its default map type
// (BTreeMap) with sorted keys; Go emits struct fields in declaration order,
// so this reproduces the exact signed bytes.
type certSignPayload struct {
	New    string `json:"new"`
	Node   string `json:"node"`
	Old    string `json:"old"`
	Pusher string `json:"pusher"`
	Ref    string `json:"ref"`
	RepoID string `json:"repo_id"`
	Ts     string `json:"ts"`
}

// canonicalCertPayload rebuilds the exact bytes the node signed.
func canonicalCertPayload(repoID, refName, oldSHA, newSHA, pusherDID, nodeDID, issuedAt string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(certSignPayload{
		New:    newSHA,
		Node:   nodeDID,
		Old:    oldSHA,
		Pusher: pusherDID,
		Ref:    refName,
		RepoID: repoID,
		Ts:     issuedAt,
	})
	// json.Encoder appends a trailing newline; the node signed without it.
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// fetchNodeDID returns the DID of the node being queried (GET / -> "did"),
// or "" when node info is unreachable.
func fetchNodeDID(c *client.NodeClient) string {
	resp, err := c.Get("/")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var info map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return ""
	}
	did, _ := info["did"].(string)
	return did
}

// CertShow retrieves a certificate and optionally verifies its signature.
func CertShow(repoInput, certID, nodeURL, dirOverride string, verify bool, expectNode string) error {
	owner, name, err := ResolveRepoOwner(repoInput, dirOverride)
	if err != nil {
		return err
	}

	kp, _ := identity.LoadKeypair(dirOverride)
	nodeURL = client.ResolveNodeURL(nodeURL)
	c := client.New(nodeURL, kp)

	resp, err := c.GetAuthed(fmt.Sprintf("/api/v1/repos/%s/%s/certs/%s", owner, name, certID))
	if err != nil {
		return fmt.Errorf("fetching cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fetching cert failed (%d): %s", resp.StatusCode, client.SanitizeNodeMsg(string(data)))
	}

	rawBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var certObj map[string]interface{}
	if err := json.Unmarshal(rawBytes, &certObj); err != nil {
		return err
	}

	if verify {
		repoID, _ := certObj["repo_id"].(string)
		refName, _ := certObj["ref_name"].(string)
		oldSHA, _ := certObj["old_sha"].(string)
		newSHA, _ := certObj["new_sha"].(string)
		pusherDID, _ := certObj["pusher_did"].(string)
		nodeDID, _ := certObj["node_did"].(string)
		issuedAt, _ := certObj["issued_at"].(string)
		if nodeDID == "" {
			return errors.New("certificate missing node_did field")
		}

		// Anchor the issuer: an explicit --expect-node wins, otherwise use
		// the DID of the node being queried. A valid signature alone only
		// proves the cert was signed by the key it names, not that it came
		// from the intended node.
		expected := expectNode
		if expected == "" {
			expected = fetchNodeDID(c)
			switch {
			case expected == nodeDID:
				fmt.Println("  Issuing node DID matches the node being queried.")
			case expected != "":
				fmt.Printf("  WARNING: Certificate node DID (%s) does not match\n", nodeDID)
				fmt.Printf("           current node DID (%s).\n", expected)
				fmt.Printf("           This certificate was issued by a different node.\n")
			default:
				fmt.Println("  NOTE: could not fetch current node info — skipping node-DID comparison.")
			}
		}

		pubKey, err := did.ToVerifyingKey(nodeDID)
		if err != nil {
			return fmt.Errorf("invalid issuer node DID: %w", err)
		}

		sigB64, _ := certObj["signature"].(string)
		if sigB64 == "" {
			return errors.New("certificate missing signature field")
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			sigBytes, err = base64.RawURLEncoding.DecodeString(sigB64)
			if err != nil {
				return fmt.Errorf("invalid signature base64: %w", err)
			}
		}

		// Verify against the canonical payload the node signed, not the
		// API record (which carries extra fields like id).
		payloadBytes := canonicalCertPayload(repoID, refName, oldSHA, newSHA, pusherDID, nodeDID, issuedAt)

		if !identity.Verify(pubKey, payloadBytes, sigBytes) {
			return errors.New("certificate signature is INVALID")
		}

		fmt.Println("✓ Certificate signature is VALID")

		if expected == "" {
			return errors.New("cannot anchor the issuer: node info is unreachable and no --expect-node was given")
		}
		if nodeDID != expected {
			return fmt.Errorf("certificate is signed by %s, but the expected issuer is %s — a valid signature alone proves internal consistency, not a trusted issuer", nodeDID, expected)
		}
	}

	pretty, _ := json.MarshalIndent(certObj, "", "  ")
	fmt.Println(string(pretty))
	return nil
}
