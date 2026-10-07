package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/Twigpine/twig/internal/identity"
)

const (
	DefaultPublicNode   = "https://node.gitlawb.com"
	LegacyPublicNode    = "https://node.gitlawb.com"
	TotalRequestTimeout = 30 * time.Second
	MaxRedirects        = 10
	MaxICaptchaRetries  = 2
	UserAgent           = "twig/0.7.1 twigpine-cli"
)

// ResolveNodeURL determines the node URL based on explicit arg, environment, or default.
func ResolveNodeURL(explicit string) string {
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	if env := os.Getenv("TWIGPINE_NODE"); env != "" {
		return strings.TrimRight(env, "/")
	}
	if env := os.Getenv("GITLAWB_NODE"); env != "" {
		return strings.TrimRight(env, "/")
	}
	return DefaultPublicNode
}

// NodeClient handles authenticated, signed HTTP requests to a Twigpine node.
type NodeClient struct {
	NodeURL string
	Keypair *identity.Keypair
	Client  *http.Client
}

// New creates a new NodeClient with the given URL and optional identity keypair.
func New(nodeURL string, keypair *identity.Keypair) *NodeClient {
	return NewWithTimeout(nodeURL, keypair, TotalRequestTimeout)
}

// NewWithTimeout creates a NodeClient with custom timeout.
func NewWithTimeout(nodeURL string, keypair *identity.Keypair, timeout time.Duration) *NodeClient {
	c := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) > 0 {
				prev := via[len(via)-1]
				// Only allow same-origin redirects
				if prev.URL.Scheme != req.URL.Scheme || prev.URL.Host != req.URL.Host {
					return http.ErrUseLastResponse
				}
			}
			return nil
		},
	}

	return &NodeClient{
		NodeURL: strings.TrimRight(nodeURL, "/"),
		Keypair: keypair,
		Client:  c,
	}
}

// SignRequest computes RFC 9421 HTTP Signatures headers for an HTTP request.
func SignRequest(keypair *identity.Keypair, method, pathAndQuery string, body []byte) (contentDigest, signatureInput, signature string) {
	created := time.Now().Unix()

	// Content-Digest: sha-256=:base64(sha256(body)):
	h := sha256.Sum256(body)
	b64Digest := base64.StdEncoding.EncodeToString(h[:])
	contentDigest = fmt.Sprintf("sha-256=:%s:", b64Digest)

	did := keypair.DID()
	sigParamsValue := fmt.Sprintf(`("@method" "@path" "content-digest");keyid="%s";alg="ed25519";created=%d`, did, created)
	signatureInput = fmt.Sprintf("sig1=%s", sigParamsValue)

	// Signing string format
	signingString := fmt.Sprintf("\"@method\": %s\n\"@path\": %s\n\"content-digest\": %s\n\"@signature-params\": %s",
		strings.ToUpper(method),
		pathAndQuery,
		contentDigest,
		sigParamsValue,
	)

	sigBytes := keypair.Sign([]byte(signingString))
	b64Sig := base64.StdEncoding.EncodeToString(sigBytes)
	signature = fmt.Sprintf("sig1=:%s:", b64Sig)

	return contentDigest, signatureInput, signature
}

// Get performs an unsigned GET request.
func (c *NodeClient) Get(path string) (*http.Response, error) {
	reqURL := c.NodeURL + path
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	return c.Client.Do(req)
}

// GetSigned performs an authenticated GET with RFC 9421 signatures over empty body.
func (c *NodeClient) GetSigned(path string) (*http.Response, error) {
	if c.Keypair == nil {
		return nil, errors.New("get_signed requires an identity keypair")
	}

	reqURL := c.NodeURL + path
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	digest, sigInput, sig := SignRequest(c.Keypair, http.MethodGet, path, []byte{})
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	return c.Client.Do(req)
}

// GetAuthed performs a signed GET if a keypair is present, else unsigned GET.
func (c *NodeClient) GetAuthed(path string) (*http.Response, error) {
	if c.Keypair != nil {
		return c.GetSigned(path)
	}
	return c.Get(path)
}

// GetMaybeSigned mirrors GetAuthed.
func (c *NodeClient) GetMaybeSigned(path string) (*http.Response, error) {
	return c.GetAuthed(path)
}

// Post sends a signed POST request with JSON body.
func (c *NodeClient) Post(path string, body []byte) (*http.Response, error) {
	return c.sendSigned(http.MethodPost, path, body)
}

// Put sends a signed PUT request with JSON body.
func (c *NodeClient) Put(path string, body []byte) (*http.Response, error) {
	return c.sendSigned(http.MethodPut, path, body)
}

// Delete sends a signed DELETE request with JSON body.
func (c *NodeClient) Delete(path string, body []byte) (*http.Response, error) {
	return c.sendSigned(http.MethodDelete, path, body)
}

func (c *NodeClient) sendSigned(method, path string, body []byte) (*http.Response, error) {
	var proof string
	attempts := 0

	for {
		resp, err := c.sendOnce(method, path, body, proof)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusUnauthorized {
			errHeader := resp.Header.Get("x-twigpine-error")
			if errHeader == "" {
				errHeader = resp.Header.Get("x-gitlawb-error")
			}
			if errHeader == "human_detected" {
				fmt.Fprintln(os.Stderr, "note: this node requires signed requests (RFC 9421). If writes keep failing, you may need to register: run `twig register`.")
			}
		}

		if resp.StatusCode == http.StatusForbidden && attempts < MaxICaptchaRetries {
			captchaURL := resp.Header.Get("x-icaptcha-url")
			captchaLevel := resp.Header.Get("x-icaptcha-level")
			if (captchaURL != "" || captchaLevel != "") && c.Keypair != nil {
				solvedProof, err := c.solveICaptcha(captchaURL, captchaLevel)
				resp.Body.Close()
				if err != nil {
					return nil, fmt.Errorf("solving iCaptcha: %w", err)
				}
				if solvedProof == "" {
					return nil, fmt.Errorf("solving iCaptcha: empty proof")
				}
				attempts++
				proof = solvedProof
				continue
			}
		}

		return resp, nil
	}
}

func (c *NodeClient) sendOnce(method, path string, body []byte, proof string) (*http.Response, error) {
	reqURL := c.NodeURL + path
	req, err := http.NewRequest(method, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request %s %s: %w", method, reqURL, err)
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")

	if c.Keypair != nil {
		digest, sigInput, sig := SignRequest(c.Keypair, method, path, body)
		req.Header.Set("Content-Digest", digest)
		req.Header.Set("Signature-Input", sigInput)
		req.Header.Set("Signature", sig)
	}

	if proof != "" {
		req.Header.Set("x-icaptcha-proof", proof)
	}

	return c.Client.Do(req)
}

// solveICaptcha obtains a proof token from the iCaptcha service for the
// x-icaptcha-proof retry header. The full challenge protocol lives in
// icaptcha.go.
func (c *NodeClient) solveICaptcha(srvURL, levelStr string) (string, error) {
	if srvURL == "" {
		srvURL = "https://icaptcha.twigpine.com"
	}

	u, err := url.Parse(srvURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid icaptcha server URL: %s", srvURL)
	}

	hostname := u.Hostname()
	ip := net.ParseIP(hostname)
	isLocal := hostname == "localhost" || (ip != nil && ip.IsLoopback())

	if u.Scheme != "https" && !(u.Scheme == "http" && isLocal) {
		return "", fmt.Errorf("insecure icaptcha server URL scheme %q: must use https for remote endpoints", u.Scheme)
	}

	if c.Keypair == nil {
		return "", fmt.Errorf("iCaptcha requires an identity")
	}
	return obtainICaptchaProof(c.Client, srvURL, c.Keypair.DID(), levelStr)
}

func countLeadingZeroBits(data []byte) int {
	bits := 0
	for _, b := range data {
		if b == 0 {
			bits += 8
		} else {
			for i := 7; i >= 0; i-- {
				if (b & (1 << i)) == 0 {
					bits++
				} else {
					return bits
				}
			}
		}
	}
	return bits
}

// CappedBody contains the result of reading a bounded response body.
type CappedBody struct {
	Text       string
	Truncated  bool
	ReadFailed bool
}

// ReadBodyCapped reads at most cap bytes from resp.Body.
func ReadBodyCapped(resp *http.Response, cap int) CappedBody {
	if resp == nil || resp.Body == nil {
		return CappedBody{}
	}
	defer resp.Body.Close()

	buf := make([]byte, 0, cap)
	temp := make([]byte, 1024)

	truncated := false
	readFailed := false

	for len(buf) < cap {
		toRead := cap - len(buf)
		if toRead > len(temp) {
			toRead = len(temp)
		}
		n, err := resp.Body.Read(temp[:toRead])
		if n > 0 {
			buf = append(buf, temp[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			readFailed = true
			break
		}
	}

	if len(buf) >= cap {
		truncated = true
	}

	return CappedBody{
		Text:       string(buf),
		Truncated:  truncated,
		ReadFailed: readFailed,
	}
}

// SanitizeNodeMsg strips terminal-dangerous control chars and Unicode bidi overrides, capping length at 200.
func SanitizeNodeMsg(s string) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= 200 {
			break
		}
		if unicode.IsControl(r) {
			continue
		}
		// Unicode bidi format characters (U+202A to U+202E, U+2066 to U+2069)
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
