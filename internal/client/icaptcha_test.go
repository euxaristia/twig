package client

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSolveArithmetic(t *testing.T) {
	cases := map[string]int64{
		"What is 12 + 7?":       19,
		"What is 12 + 7 - 3?":   16,
		"What is 100 - 58 + 3?": 45,
	}
	for prompt, want := range cases {
		got, ok := solveArithmetic(prompt)
		if !ok || got != want {
			t.Errorf("solveArithmetic(%q) = %d,%v; want %d,true", prompt, got, ok, want)
		}
	}
	if _, ok := solveArithmetic("What is 2 * 3?"); ok {
		t.Errorf("expected failure for unsupported operator")
	}
}

func TestSolveAlgebra(t *testing.T) {
	cases := map[string]int64{
		"Solve for x: 3x + 4 = 19":    5,
		"Solve for x: x - 7 = 3":      10,
		"Solve for x: 2(x + 3) = 16":  5,
		"Solve for x: 2x + 3 = x + 8": 5,
	}
	for prompt, want := range cases {
		got, ok := solveAlgebra(prompt)
		if !ok || got != want {
			t.Errorf("solveAlgebra(%q) = %d,%v; want %d,true", prompt, got, ok, want)
		}
	}
}

func TestSolveSequence(t *testing.T) {
	cases := map[string]int64{
		"What is the next number in this sequence? 2, 4, 6, 8, 10, ?": 12,
		"What is the next number in this sequence? 3, 9, 27, ?":       81,
		"What is the next number in this sequence? 1, 1, 2, 3, 5, ?":  8,
		"What is the next number in this sequence? 1, 4, 9, 16, ?":    25,
	}
	for prompt, want := range cases {
		got, ok := solveSequence(prompt)
		if !ok || got != want {
			t.Errorf("solveSequence(%q) = %d,%v; want %d,true", prompt, got, ok, want)
		}
	}
}

func TestSolveICaptchaPow(t *testing.T) {
	p := &icaptchaPow{Algorithm: icaptchaPowAlgo, Challenge: "test-challenge", Difficulty: 8}
	nonce, err := solveICaptchaPow(p)
	if err != nil {
		t.Fatalf("solveICaptchaPow failed: %v", err)
	}
	hash := sha256.Sum256([]byte("test-challenge:" + nonce))
	if countLeadingZeroBits(hash[:]) < 8 {
		t.Fatalf("nonce %q does not meet difficulty", nonce)
	}
	if _, err := solveICaptchaPow(&icaptchaPow{Algorithm: "bogus", Challenge: "x", Difficulty: 8}); err == nil {
		t.Fatalf("expected error for unknown PoW algorithm")
	}
}

// mockICaptcha serves the challenge/answer protocol and records requests.
type mockICaptcha struct {
	t               *testing.T
	challengeBodies []map[string]interface{}
	answerBodies    []map[string]interface{}
	answerHandler   func(answer map[string]interface{}) map[string]interface{}
}

func (m *mockICaptcha) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var parsed map[string]interface{}
	_ = json.Unmarshal(body, &parsed)
	switch r.URL.Path {
	case "/v1/challenge":
		m.challengeBodies = append(m.challengeBodies, parsed)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "arithmetic", "difficulty": 1,
			"prompt": "What is 40 + 2?", "token": "tok-1",
		})
	case "/v1/answer":
		m.answerBodies = append(m.answerBodies, parsed)
		_ = json.NewEncoder(w).Encode(m.answerHandler(parsed))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestObtainICaptchaProofFullFlow(t *testing.T) {
	m := &mockICaptcha{t: t}
	m.answerHandler = func(answer map[string]interface{}) map[string]interface{} {
		if answer["token"] != "tok-1" {
			t.Errorf("answer missing token, got %v", answer)
		}
		if answer["answer"] != "42" {
			t.Errorf("answer wrong, got %v", answer)
		}
		if _, ok := answer["challengeId"]; ok {
			t.Errorf("legacy challengeId field must not be sent")
		}
		return map[string]interface{}{"status": "passed", "proof": "proof-abc"}
	}
	srv := httptest.NewServer(m)
	defer srv.Close()

	proof, err := obtainICaptchaProof(srv.Client(), srv.URL, "did:key:z6MkTest", "5")
	if err != nil {
		t.Fatalf("obtainICaptchaProof failed: %v", err)
	}
	if proof != "proof-abc" {
		t.Fatalf("proof = %q", proof)
	}
	// requiredLevel must be sent as a number on the challenge request.
	if len(m.challengeBodies) != 1 {
		t.Fatalf("expected 1 challenge request, got %d", len(m.challengeBodies))
	}
	cb := m.challengeBodies[0]
	if cb["requiredLevel"] != float64(5) {
		t.Errorf("requiredLevel not sent as number: %v", cb)
	}
	if cb["requesterId"] != "did:key:z6MkTest" {
		t.Errorf("requesterId not sent: %v", cb)
	}
}

func TestObtainICaptchaProofContinuation(t *testing.T) {
	m := &mockICaptcha{t: t}
	calls := 0
	m.answerHandler = func(answer map[string]interface{}) map[string]interface{} {
		calls++
		if calls == 1 {
			return map[string]interface{}{
				"status": "continue",
				"challenge": map[string]interface{}{
					"type": "arithmetic", "difficulty": 1,
					"prompt": "What is 1 + 1?", "token": "tok-2",
				},
			}
		}
		if answer["token"] != "tok-2" || answer["answer"] != "2" {
			t.Errorf("continuation answer wrong: %v", answer)
		}
		return map[string]interface{}{"status": "passed", "proof": "proof-2"}
	}
	srv := httptest.NewServer(m)
	defer srv.Close()

	proof, err := obtainICaptchaProof(srv.Client(), srv.URL, "did:key:z6MkTest", "")
	if err != nil {
		t.Fatalf("obtainICaptchaProof failed: %v", err)
	}
	if proof != "proof-2" {
		t.Fatalf("proof = %q", proof)
	}
}

func TestObtainICaptchaProofFailed(t *testing.T) {
	m := &mockICaptcha{t: t}
	m.answerHandler = func(answer map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"status": "failed", "reason": "wrong answer"}
	}
	srv := httptest.NewServer(m)
	defer srv.Close()

	_, err := obtainICaptchaProof(srv.Client(), srv.URL, "did:key:z6MkTest", "")
	if err == nil || !strings.Contains(err.Error(), "wrong answer") {
		t.Fatalf("expected failure reason, got: %v", err)
	}
}

func TestObtainICaptchaProofWithPow(t *testing.T) {
	m := &mockICaptcha{t: t}
	powSeen := ""
	m.answerHandler = func(answer map[string]interface{}) map[string]interface{} {
		if pn, ok := answer["powNonce"].(string); ok {
			powSeen = pn
		} else {
			t.Errorf("powNonce not sent: %v", answer)
		}
		return map[string]interface{}{"status": "passed", "proof": "proof-pow"}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/challenge" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "arithmetic", "difficulty": 1,
				"prompt": "What is 2 + 2?", "token": "tok-pow",
				"pow": map[string]interface{}{
					"algorithm": icaptchaPowAlgo, "challenge": "pow-chal", "difficulty": 8,
				},
			})
			return
		}
		m.ServeHTTP(w, r)
	}))
	defer srv.Close()

	proof, err := obtainICaptchaProof(srv.Client(), srv.URL, "did:key:z6MkTest", "")
	if err != nil {
		t.Fatalf("obtainICaptchaProof failed: %v", err)
	}
	if proof != "proof-pow" || powSeen == "" {
		t.Fatalf("proof=%q powNonce=%q", proof, powSeen)
	}
	hash := sha256.Sum256([]byte("pow-chal:" + powSeen))
	if countLeadingZeroBits(hash[:]) < 8 {
		t.Fatalf("powNonce does not satisfy PoW")
	}
}
