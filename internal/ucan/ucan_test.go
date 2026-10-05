package ucan

import (
	"testing"
	"time"

	"github.com/Twigpine/twig/internal/identity"
)

func TestUcanIssueAndVerify(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	audKp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate audience keypair failed: %v", err)
	}

	exp := time.Now().Add(1 * time.Hour)
	token, err := Issue(
		kp,
		audKp.DID(),
		[]Capability{
			{With: "twigpine://repos/owner/repo", Can: GitPush},
		},
		&exp,
	)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	if token.IsExpired() {
		t.Fatalf("newly issued token should not be expired")
	}

	if err := token.VerifySignature(); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	encoded, err := token.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Payload.Iss != kp.DID() {
		t.Fatalf("issuer mismatch: %s != %s", decoded.Payload.Iss, kp.DID())
	}
	if decoded.Payload.Aud != audKp.DID() {
		t.Fatalf("audience mismatch: %s != %s", decoded.Payload.Aud, audKp.DID())
	}
	if err := decoded.VerifySignature(); err != nil {
		t.Fatalf("decoded token signature verification failed: %v", err)
	}
}

func TestUcanExpiration(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	past := time.Now().Add(-1 * time.Hour)
	token, err := Issue(
		kp,
		kp.DID(),
		[]Capability{{With: "*", Can: "*"}},
		&past,
	)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	if !token.IsExpired() {
		t.Fatalf("expected token to be expired")
	}
}

func TestUcanNotBefore(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	futureNbf := time.Now().Add(1 * time.Hour).Unix()
	token := &Ucan{
		Payload: UcanPayload{
			Ucan: "1.0.0",
			Iss:  kp.DID(),
			Aud:  kp.DID(),
			Att:  []Capability{{With: "*", Can: "*"}},
			Nbf:  &futureNbf,
		},
	}

	if !token.IsBeforeValid() {
		t.Fatalf("expected token to be invalid before nbf timestamp")
	}

	pastNbf := time.Now().Add(-1 * time.Hour).Unix()
	validToken := &Ucan{
		Payload: UcanPayload{
			Nbf: &pastNbf,
		},
	}

	if validToken.IsBeforeValid() {
		t.Fatalf("expected token with past nbf to be valid")
	}
}
