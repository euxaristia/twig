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
	if token.IsValid() {
		t.Fatalf("expired token should not be valid")
	}
}

func TestUcanNotBefore(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	futureNbf := time.Now().Add(1 * time.Hour).Unix()
	exp := time.Now().Add(2 * time.Hour)

	token, err := Issue(
		kp,
		kp.DID(),
		[]Capability{{With: "*", Can: "*"}},
		&exp,
	)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	token.Payload.Nbf = &futureNbf

	if !token.IsBeforeValid() {
		t.Fatalf("expected token with future nbf to return true for IsBeforeValid()")
	}

	if token.IsValid() {
		t.Fatalf("expected token with future nbf to return false for IsValid()")
	}
}

func TestUcanDecodeJSONAndNilFieldNormalization(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}

	token, err := Issue(
		kp,
		kp.DID(),
		[]Capability{{With: "twigpine://test", Can: "read"}},
		nil,
	)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	encoded, err := token.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	// Decoding raw JSON string directly without Stat
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Force nil Prf (simulating omitted "prf" array during unmarshaling)
	decoded.Payload.Prf = nil

	if err := decoded.VerifySignature(); err != nil {
		t.Fatalf("VerifySignature should succeed after normalizing nil Prf: %v", err)
	}
}
