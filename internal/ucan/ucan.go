package ucan

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Twigpine/twig/internal/did"
	"github.com/Twigpine/twig/internal/identity"
)

// Well-known capability constants.
const (
	GitPush     = "git/push"
	GitFetch    = "git/fetch"
	PrOpen      = "pr/open"
	PrMerge     = "pr/merge"
	PrReview    = "pr/review"
	IssueCreate = "issue/create"
	IssueClose  = "issue/close"
	NetworkJoin = "network/join"
	AgentDeploy = "agent/deploy"
	RepoAdmin   = "repo/admin"
)

// Capability defines a resource and action authorization.
type Capability struct {
	With        string                 `json:"with"`
	Can         string                 `json:"can"`
	Constraints map[string]interface{} `json:"nb,omitempty"`
}

// UcanPayload is the signed body of a UCAN token.
type UcanPayload struct {
	Ucan string       `json:"ucan"`
	Iss  string       `json:"iss"`
	Aud  string       `json:"aud"`
	Att  []Capability `json:"att"`
	Exp  *int64       `json:"exp,omitempty"`
	Nbf  *int64       `json:"nbf,omitempty"`
	Prf  []string     `json:"prf"`
}

// Ucan represents a full signed UCAN token.
type Ucan struct {
	Payload UcanPayload `json:"payload"`
	S       string      `json:"s"`
}

// Issue generates and signs a new UCAN token.
func Issue(issuer *identity.Keypair, audience string, capabilities []Capability, exp *time.Time) (*Ucan, error) {
	var expSec *int64
	if exp != nil {
		sec := exp.Unix()
		expSec = &sec
	}

	payload := UcanPayload{
		Ucan: "1.0.0",
		Iss:  issuer.DID(),
		Aud:  audience,
		Att:  capabilities,
		Exp:  expSec,
		Prf:  []string{},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UCAN payload: %w", err)
	}

	sigB64 := issuer.SignB64(payloadBytes)

	return &Ucan{
		Payload: payload,
		S:       sigB64,
	}, nil
}

// Bootstrap creates a 30-day bootstrap UCAN granting network/join.
func Bootstrap(issuer *identity.Keypair, audience string) (*Ucan, error) {
	exp := time.Now().Add(30 * 24 * time.Hour)
	return Issue(
		issuer,
		audience,
		[]Capability{{With: "twigpine://alpha", Can: NetworkJoin}},
		&exp,
	)
}

// IsExpired checks if the token is past its expiration date.
func (u *Ucan) IsExpired() bool {
	if u.Payload.Exp == nil {
		return false
	}
	return time.Now().Unix() > *u.Payload.Exp
}

// IsBeforeValid checks if the token is before its not-before date.
func (u *Ucan) IsBeforeValid() bool {
	if u.Payload.Nbf == nil {
		return false
	}
	return time.Now().Unix() < *u.Payload.Nbf
}

// IsValid returns true if signature is valid, token is not expired, and not before date has passed.
func (u *Ucan) IsValid() bool {
	return u.VerifySignature() == nil && !u.IsExpired() && !u.IsBeforeValid()
}

// VerifySignature validates the cryptographic Ed25519 signature of the UCAN token.
func (u *Ucan) VerifySignature() error {
	pubKey, err := did.ToVerifyingKey(u.Payload.Iss)
	if err != nil {
		return fmt.Errorf("invalid issuer DID: %w", err)
	}

	payload := u.Payload
	if payload.Prf == nil {
		payload.Prf = []string{}
	}
	if payload.Att == nil {
		payload.Att = []Capability{}
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(u.S)
	if err != nil {
		// Try standard URLEncoding fallback
		sigBytes, err = base64.URLEncoding.DecodeString(u.S)
		if err != nil {
			return fmt.Errorf("failed to decode signature base64: %w", err)
		}
	}

	if !identity.Verify(pubKey, payloadBytes, sigBytes) {
		return errors.New("signature is invalid")
	}

	return nil
}

// Encode serializes the Ucan to a pretty-printed JSON string.
func (u *Ucan) Encode() (string, error) {
	bytes, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Decode parses a UCAN from raw JSON text or a file path containing JSON.
func Decode(input string) (*Ucan, error) {
	trimmed := strings.TrimSpace(input)
	var data []byte

	// Check if input is a file path (only when not direct JSON string)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		if _, err := os.Stat(trimmed); err == nil {
			fileBytes, err := os.ReadFile(trimmed)
			if err != nil {
				return nil, fmt.Errorf("reading token file: %w", err)
			}
			data = fileBytes
		} else {
			data = []byte(trimmed)
		}
	} else {
		data = []byte(trimmed)
	}

	var u Ucan
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, fmt.Errorf("parsing UCAN JSON: %w", err)
	}

	if u.Payload.Ucan == "" || u.Payload.Iss == "" {
		return nil, errors.New("invalid UCAN structure: missing required payload fields")
	}

	return &u, nil
}
