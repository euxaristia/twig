package commands

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Twigpine/twig/internal/identity"
)

type testCertFixture struct {
	record  map[string]interface{}
	nodeDID string
}

// makeCert builds a deterministic certificate fixture using the node's
// signing format: the canonical payload is signed with the issuer's key and
// the record carries the node's DB field names (including extra metadata
// like id that must not affect verification).
func makeCert(t *testing.T, issuer *identity.Keypair, nodeDID, issuedAt string) testCertFixture {
	t.Helper()
	payload := canonicalCertPayload("repo1", "refs/heads/main",
		"0000000000000000000000000000000000000000",
		"1111111111111111111111111111111111111111",
		issuer.DID(), nodeDID, issuedAt)
	sig := base64.RawURLEncoding.EncodeToString(issuer.Sign(payload))
	return testCertFixture{
		nodeDID: nodeDID,
		record: map[string]interface{}{
			"id":         "cert-123",
			"repo_id":    "repo1",
			"ref_name":   "refs/heads/main",
			"old_sha":    "0000000000000000000000000000000000000000",
			"new_sha":    "1111111111111111111111111111111111111111",
			"pusher_did": issuer.DID(),
			"node_did":   nodeDID,
			"signature":  sig,
			"issued_at":  issuedAt,
		},
	}
}

func certServer(t *testing.T, fix testCertFixture, nodeInfoStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			if nodeInfoStatus != http.StatusOK {
				w.WriteHeader(nodeInfoStatus)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"did": fix.nodeDID})
		case strings.HasPrefix(r.URL.Path, "/api/v1/repos/") && strings.Contains(r.URL.Path, "/certs/"):
			_ = json.NewEncoder(w).Encode(fix.record)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func certIdentityDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := IdentityNew(dir, false, strings.NewReader("")); err != nil {
		t.Fatalf("IdentityNew failed: %v", err)
	}
	return dir
}

const testIssuedAt = "2026-10-04T12:00:00+00:00"

// TestCertShowVerifyAnchorsIssuer: a genuine node certificate verifies and
// the issuer is anchored to the queried node's DID by default.
func TestCertShowVerifyAnchorsIssuer(t *testing.T) {
	nodeKP, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	fix := makeCert(t, nodeKP, nodeKP.DID(), testIssuedAt)
	srv := certServer(t, fix, http.StatusOK)
	defer srv.Close()

	if err := CertShow("o/r", "cert-123", srv.URL, certIdentityDir(t), true, ""); err != nil {
		t.Fatalf("CertShow verify failed: %v", err)
	}
}

// TestCertShowVerifyCanonicalPayload: record metadata (id) must not alter the
// verification bytes; tampering with a signed field breaks the signature.
func TestCertShowVerifyCanonicalPayload(t *testing.T) {
	nodeKP, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	fix := makeCert(t, nodeKP, nodeKP.DID(), testIssuedAt)
	// Tamper after signing: the signature no longer matches.
	fix.record["new_sha"] = "2222222222222222222222222222222222222222"
	srv := certServer(t, fix, http.StatusOK)
	defer srv.Close()

	err = CertShow("o/r", "cert-123", srv.URL, certIdentityDir(t), true, "")
	if err == nil || !strings.Contains(err.Error(), "INVALID") {
		t.Fatalf("expected INVALID signature error, got: %v", err)
	}
}

// TestCertShowRejectsForeignIssuer: a cryptographically valid certificate
// from a different identity is rejected because the issuer is anchored to
// the queried node.
func TestCertShowRejectsForeignIssuer(t *testing.T) {
	nodeKP, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	attackerKP, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	// Attacker mints a self-consistent cert naming their own DID...
	fix := makeCert(t, attackerKP, attackerKP.DID(), testIssuedAt)
	// ...but the node being queried is the real one.
	fix.nodeDID = nodeKP.DID()
	srv := certServer(t, fix, http.StatusOK)
	defer srv.Close()

	err = CertShow("o/r", "cert-123", srv.URL, certIdentityDir(t), true, "")
	if err == nil || !strings.Contains(err.Error(), "expected issuer") {
		t.Fatalf("expected issuer-mismatch error, got: %v", err)
	}
}

// TestCertShowRequiresIssuerAnchor: when node info is unreachable and no
// --expect-node is given, verification must fail closed.
func TestCertShowRequiresIssuerAnchor(t *testing.T) {
	nodeKP, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	fix := makeCert(t, nodeKP, nodeKP.DID(), testIssuedAt)
	srv := certServer(t, fix, http.StatusInternalServerError)
	defer srv.Close()

	err = CertShow("o/r", "cert-123", srv.URL, certIdentityDir(t), true, "")
	if err == nil || !strings.Contains(err.Error(), "cannot anchor the issuer") {
		t.Fatalf("expected anchor error, got: %v", err)
	}
}

// TestCertShowExpectNodeFlag: an explicit --expect-node is enforced.
func TestCertShowExpectNodeFlag(t *testing.T) {
	nodeKP, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	otherKP, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	fix := makeCert(t, nodeKP, nodeKP.DID(), testIssuedAt)
	srv := certServer(t, fix, http.StatusInternalServerError)
	defer srv.Close()
	idDir := certIdentityDir(t)

	if err := CertShow("o/r", "cert-123", srv.URL, idDir, true, nodeKP.DID()); err != nil {
		t.Fatalf("matching --expect-node should verify: %v", err)
	}
	err = CertShow("o/r", "cert-123", srv.URL, idDir, true, otherKP.DID())
	if err == nil || !strings.Contains(err.Error(), "expected issuer") {
		t.Fatalf("expected issuer-mismatch error, got: %v", err)
	}
}
