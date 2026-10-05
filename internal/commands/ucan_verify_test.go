package commands

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Twigpine/twig/internal/identity"
	"github.com/Twigpine/twig/internal/ucan"
)

// signWithNbf issues a token, sets its nbf claim, and re-signs it so the
// signature covers the nbf value.
func signWithNbf(t *testing.T, kp *identity.Keypair, nbf int64) string {
	t.Helper()

	exp := time.Now().Add(1 * time.Hour)
	token, err := ucan.Issue(
		kp,
		kp.DID(),
		[]ucan.Capability{{With: "*", Can: "*"}},
		&exp,
	)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	token.Payload.Nbf = &nbf
	payloadBytes, err := json.Marshal(token.Payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	token.S = kp.SignB64(payloadBytes)

	encoded, err := token.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return encoded
}

func TestUcanVerifyRejectsFutureNbf(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	futureNbf := time.Now().Add(1 * time.Hour).Unix()
	encoded := signWithNbf(t, kp, futureNbf)

	err = UcanVerify(encoded)
	if err == nil {
		t.Fatalf("expected UcanVerify to reject a token with future nbf, got nil")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("expected 'not yet valid' error, got: %v", err)
	}
}

func TestUcanVerifyAcceptsPastNbf(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	pastNbf := time.Now().Add(-1 * time.Hour).Unix()
	encoded := signWithNbf(t, kp, pastNbf)

	if err := UcanVerify(encoded); err != nil {
		t.Fatalf("expected UcanVerify to accept a token with past nbf, got: %v", err)
	}
}
