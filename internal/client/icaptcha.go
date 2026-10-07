package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// iCaptcha challenge protocol (mirrors crates/icaptcha-client).
//
// The service gates writes behind computational challenges: the client
// requests a challenge, solves its prompt (and any proof-of-work), submits
// the answer with the challenge token, and retries on continuation
// challenges until the service returns a proof token.

const (
	icaptchaMaxRounds   = 8
	icaptchaPowMaxIters = 1 << 26
	icaptchaPowAlgo     = "sha256-leading-zero-bits"
)

var icaptchaSolvableTypes = []string{"arithmetic", "algebra", "sequence"}

type icaptchaPow struct {
	Algorithm  string `json:"algorithm"`
	Challenge  string `json:"challenge"`
	Difficulty int    `json:"difficulty"`
}

type icaptchaChallenge struct {
	Kind       string       `json:"type"`
	Difficulty int          `json:"difficulty"`
	Prompt     string       `json:"prompt"`
	Token      string       `json:"token"`
	Pow        *icaptchaPow `json:"pow"`
}

type icaptchaAnswerResult struct {
	Status    string             `json:"status"`
	Proof     string             `json:"proof"`
	Reason    string             `json:"reason"`
	Challenge *icaptchaChallenge `json:"challenge"`
}

// obtainICaptchaProof runs the challenge -> solve -> answer loop and returns
// a fresh proof token for the original request's x-icaptcha-proof header.
func obtainICaptchaProof(httpClient *http.Client, srvURL, did, level string) (string, error) {
	srvURL = strings.TrimRight(srvURL, "/")

	challenge, err := requestICaptchaChallenge(httpClient, srvURL, did, level)
	if err != nil {
		return "", err
	}

	for round := 0; round < icaptchaMaxRounds; round++ {
		answer, err := solveICaptchaChallenge(challenge.Kind, challenge.Prompt)
		if err != nil {
			return "", err
		}

		var powNonce *string
		if challenge.Pow != nil {
			nonce, err := solveICaptchaPow(challenge.Pow)
			if err != nil {
				return "", err
			}
			powNonce = &nonce
		}

		result, err := submitICaptchaAnswer(httpClient, srvURL, challenge.Token, answer, powNonce)
		if err != nil {
			return "", err
		}

		switch result.Status {
		case "passed":
			return result.Proof, nil
		case "continue":
			if result.Challenge == nil {
				return "", fmt.Errorf("iCaptcha continuation missing challenge")
			}
			challenge = result.Challenge
		case "failed":
			return "", fmt.Errorf("iCaptcha challenge failed: %s", SanitizeNodeMsg(result.Reason))
		default:
			return "", fmt.Errorf("unknown iCaptcha answer status %q", result.Status)
		}
	}
	return "", fmt.Errorf("iCaptcha not solved within %d rounds", icaptchaMaxRounds)
}

func requestICaptchaChallenge(httpClient *http.Client, srvURL, did, level string) (*icaptchaChallenge, error) {
	// The Rust config models required_level as u32 (default 3); the
	// challenge request carries it as a JSON number to match.
	levelNum := 3
	if n, err := strconv.Atoi(strings.TrimSpace(level)); err == nil && n >= 0 {
		levelNum = n
	}
	reqBody, _ := json.Marshal(map[string]interface{}{
		"requesterId":   did,
		"requiredLevel": levelNum,
		"types":         icaptchaSolvableTypes,
	})
	resp, err := httpClient.Post(srvURL+"/v1/challenge", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("iCaptcha challenge request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("iCaptcha challenge request failed (%d)", resp.StatusCode)
	}
	var challenge icaptchaChallenge
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		return nil, fmt.Errorf("parsing iCaptcha challenge: %w", err)
	}
	if challenge.Token == "" {
		return nil, fmt.Errorf("iCaptcha challenge missing token")
	}
	return &challenge, nil
}

func submitICaptchaAnswer(httpClient *http.Client, srvURL, token, answer string, powNonce *string) (*icaptchaAnswerResult, error) {
	body := map[string]interface{}{
		"token":  token,
		"answer": answer,
	}
	if powNonce != nil {
		body["powNonce"] = *powNonce
	}
	reqBody, _ := json.Marshal(body)
	resp, err := httpClient.Post(srvURL+"/v1/answer", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("iCaptcha answer request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("iCaptcha answer request failed (%d)", resp.StatusCode)
	}
	var result icaptchaAnswerResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing iCaptcha answer result: %w", err)
	}
	return &result, nil
}

// solveICaptchaPow finds a nonce such that
// sha256("{challenge}:{nonce}") has at least difficulty leading zero bits.
// Only the service's algorithm is accepted; anything else is a hard error.
func solveICaptchaPow(p *icaptchaPow) (string, error) {
	if p.Algorithm != icaptchaPowAlgo {
		return "", fmt.Errorf("unknown iCaptcha PoW algorithm %q", p.Algorithm)
	}
	if p.Difficulty == 0 {
		return "0", nil
	}
	for i := 0; i < icaptchaPowMaxIters; i++ {
		nonce := fmt.Sprintf("%x", i)
		hash := sha256.Sum256([]byte(p.Challenge + ":" + nonce))
		if countLeadingZeroBits(hash[:]) >= p.Difficulty {
			return nonce, nil
		}
	}
	return "", fmt.Errorf("iCaptcha PoW not solved within iteration cap (difficulty %d)", p.Difficulty)
}

// solveICaptchaChallenge solves the deterministic challenge types.
// The service grades numerics by value, so the plain integer string suffices.
func solveICaptchaChallenge(kind, prompt string) (string, error) {
	var n int64
	var ok bool
	switch kind {
	case "arithmetic":
		n, ok = solveArithmetic(prompt)
	case "algebra":
		n, ok = solveAlgebra(prompt)
	case "sequence":
		n, ok = solveSequence(prompt)
	default:
		return "", fmt.Errorf("cannot solve iCaptcha challenge type %q automatically", kind)
	}
	if !ok {
		return "", fmt.Errorf("could not parse iCaptcha %s challenge", kind)
	}
	return strconv.FormatInt(n, 10), nil
}

// "What is 12 + 7 - 3?" -> evaluate the additive chain left to right.
func solveArithmetic(prompt string) (int64, bool) {
	expr, ok := strings.CutPrefix(strings.TrimSpace(prompt), "What is ")
	if !ok {
		return 0, false
	}
	expr = strings.TrimSuffix(strings.TrimSpace(expr), "?")
	tokens := strings.Fields(expr)
	if len(tokens) == 0 {
		return 0, false
	}
	acc, err := strconv.ParseInt(tokens[0], 10, 64)
	if err != nil {
		return 0, false
	}
	for i := 1; i+1 < len(tokens); i += 2 {
		n, err := strconv.ParseInt(tokens[i+1], 10, 64)
		if err != nil {
			return 0, false
		}
		switch tokens[i] {
		case "+":
			acc += n
		case "-":
			acc -= n
		default:
			return 0, false
		}
	}
	if len(tokens)%2 == 0 {
		return 0, false
	}
	return acc, true
}

// "Solve for x: 3x + 4 = 19" -> parse each side into coeff*x + const,
// then x = (cR - cL) / (aL - aR).
func solveAlgebra(prompt string) (int64, bool) {
	eq, ok := strings.CutPrefix(strings.TrimSpace(prompt), "Solve for x:")
	if !ok {
		return 0, false
	}
	lhs, rhs, ok := strings.Cut(strings.TrimSpace(eq), "=")
	if !ok {
		return 0, false
	}
	al, cl, ok := parseLinear(lhs)
	if !ok {
		return 0, false
	}
	ar, cr, ok := parseLinear(rhs)
	if !ok {
		return 0, false
	}
	denom := al - ar
	if denom == 0 {
		return 0, false
	}
	num := cr - cl
	if num%denom != 0 {
		return 0, false
	}
	return num / denom, true
}

// parseLinear parses a linear expression in x into (coeff_of_x, constant).
// Handles Nx, x, integer constants, and a single N(x +/- M) product.
func parseLinear(s string) (int64, int64, bool) {
	s = strings.TrimSpace(s)
	if open := strings.IndexByte(s, '('); open >= 0 {
		a, err := strconv.ParseInt(strings.TrimSpace(s[:open]), 10, 64)
		if err != nil {
			return 0, 0, false
		}
		closeIdx := strings.IndexByte(s, ')')
		if closeIdx < 0 {
			return 0, 0, false
		}
		inner := strings.Fields(s[open+1 : closeIdx])
		if len(inner) == 0 || inner[0] != "x" {
			return 0, 0, false
		}
		var ci, ki int64 = 1, 0
		if len(inner) > 1 {
			if len(inner) != 3 {
				return 0, 0, false
			}
			m, err := strconv.ParseInt(inner[2], 10, 64)
			if err != nil {
				return 0, 0, false
			}
			switch inner[1] {
			case "+":
				ki = m
			case "-":
				ki = -m
			default:
				return 0, 0, false
			}
		}
		return a * ci, a * ki, true
	}

	var coeff, konst, sign int64 = 0, 0, 1
	for _, tok := range strings.Fields(s) {
		switch tok {
		case "+":
			sign = 1
		case "-":
			sign = -1
		default:
			if cpart, isX := strings.CutSuffix(tok, "x"); isX {
				var c int64
				switch cpart {
				case "", "+":
					c = 1
				case "-":
					c = -1
				default:
					var err error
					c, err = strconv.ParseInt(cpart, 10, 64)
					if err != nil {
						return 0, 0, false
					}
				}
				coeff += sign * c
			} else {
				n, err := strconv.ParseInt(tok, 10, 64)
				if err != nil {
					return 0, 0, false
				}
				konst += sign * n
			}
			sign = 1
		}
	}
	return coeff, konst, true
}

// "What is the next number in this sequence? 2, 4, 6, 8, 10, ?"
func solveSequence(prompt string) (int64, bool) {
	_, tail, ok := strings.Cut(prompt, "sequence?")
	if !ok {
		return 0, false
	}
	var nums []int64
	for _, t := range strings.Split(tail, ",") {
		if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			nums = append(nums, n)
		}
	}
	if len(nums) < 3 {
		return 0, false
	}
	return nextInSequence(nums)
}

func nextInSequence(n []int64) (int64, bool) {
	last := n[len(n)-1]

	// Arithmetic: constant first difference.
	d := n[1] - n[0]
	all := true
	for i := 1; i < len(n); i++ {
		if n[i]-n[i-1] != d {
			all = false
			break
		}
	}
	if all {
		return last + d, true
	}

	// Geometric: constant integer ratio.
	if n[0] != 0 && n[1]%n[0] == 0 {
		r := n[1] / n[0]
		geo := r != 0
		for i := 1; i < len(n) && geo; i++ {
			if n[i-1] == 0 || n[i] != n[i-1]*r {
				geo = false
			}
		}
		if geo {
			return last * r, true
		}
	}

	// Fibonacci-like: each term is the sum of the two before it.
	if len(n) >= 3 {
		fib := true
		for i := 2; i < len(n); i++ {
			if n[i] != n[i-1]+n[i-2] {
				fib = false
				break
			}
		}
		if fib {
			return n[len(n)-1] + n[len(n)-2], true
		}
	}

	// Squares: all perfect squares with consecutive roots.
	roots := make([]int64, len(n))
	squares := true
	for i, v := range n {
		r, ok := isqrtExact(v)
		if !ok {
			squares = false
			break
		}
		roots[i] = r
	}
	if squares {
		consec := true
		for i := 1; i < len(roots); i++ {
			if roots[i] != roots[i-1]+1 {
				consec = false
				break
			}
		}
		if consec {
			nr := roots[len(roots)-1] + 1
			return nr * nr, true
		}
	}

	// Alternating sign over an arithmetic magnitude.
	alt := true
	for i, v := range n {
		if i%2 == 0 && v < 0 {
			alt = false
			break
		}
		if i%2 == 1 && v >= 0 {
			alt = false
			break
		}
	}
	if alt {
		md := abs64(n[1]) - abs64(n[0])
		magsOK := true
		for i := 1; i < len(n); i++ {
			if abs64(n[i])-abs64(n[i-1]) != md {
				magsOK = false
				break
			}
		}
		if magsOK {
			nextMag := abs64(last) + md
			if last >= 0 {
				return -nextMag, true
			}
			return nextMag, true
		}
	}

	return 0, false
}

func isqrtExact(v int64) (int64, bool) {
	if v < 0 {
		return 0, false
	}
	// Binary search for the exact root. mid*mid can overflow int64, so the
	// comparison uses division: mid*mid < v  <=>  mid < v/mid  <=>
	// q > mid or (q == mid and r > 0), where q, r = v/mid, v%mid.
	lo, hi := int64(0), int64(1)<<32
	if hi > v {
		hi = v
	}
	for lo <= hi {
		mid := (lo + hi) / 2
		if mid == 0 {
			if v == 0 {
				return 0, true
			}
			lo = 1
			continue
		}
		q, r := v/mid, v%mid
		if r == 0 && q == mid {
			return mid, true
		}
		if q > mid || (q == mid && r > 0) {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return 0, false
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
