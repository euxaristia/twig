package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
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

// GitURLScheme returns the URL scheme matching an installed git remote
// helper: "twigpine" when git-remote-twigpine is on PATH, "gitlawb" when only
// the legacy git-remote-gitlawb is available. Defaults to "twigpine" so
// generated URLs keep working once the helper is installed.
func GitURLScheme() string {
	if _, err := exec.LookPath("git-remote-twigpine"); err == nil {
		return "twigpine"
	}
	if _, err := exec.LookPath("git-remote-gitlawb"); err == nil {
		return "gitlawb"
	}
	return "twigpine"
}

// ValidateEndpointURL verifies that an external URL input is non-empty, well-formed,
// has an http or https scheme, and contains a valid host.
func ValidateEndpointURL(rawURL string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return errors.New("URL cannot be empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid URL %q: must be a valid HTTP or HTTPS URL", rawURL)
	}
	return nil
}

// FormatGitURL builds a repository git URL using the scheme of the installed
// remote helper, so the URL is usable with the helper on PATH.
func FormatGitURL(owner, repo string) string {
	return fmt.Sprintf("%s://%s/%s", GitURLScheme(), owner, repo)
}

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

				// SECURITY: Strip sensitive RFC 9421 signatures and proof headers on redirects.
				// Signatures bind @path (which changes on redirect) and proof headers should not leak.
				req.Header.Del("Signature")
				req.Header.Del("Signature-Input")
				req.Header.Del("Content-Digest")
				req.Header.Del("x-icaptcha-proof")
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

func toUpperASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			return strings.ToUpper(s)
		}
	}
	return s
}

// SignRequest computes RFC 9421 HTTP Signatures headers for an HTTP request.
// Optimized: Uses fixed stack slice buffers for signature parameters and payload
// construction, and formats signatureInput directly into a single string allocation.
func SignRequest(keypair *identity.Keypair, method, pathAndQuery string, body []byte) (contentDigest, signatureInput, signature string) {
	created := time.Now().Unix()

	// Content-Digest: sha-256=:base64(sha256(body)):
	h := sha256.Sum256(body)
	var digestBuf [54]byte
	copy(digestBuf[:9], "sha-256=:")
	base64.StdEncoding.Encode(digestBuf[9:53], h[:])
	digestBuf[53] = ':'
	contentDigest = string(digestBuf[:])

	did := keypair.DID()

	var createdBuf [20]byte
	createdBytes := strconv.AppendInt(createdBuf[:0], created, 10)

	sigParamsLen := 44 + len(did) + 24 + len(createdBytes)
	var sigParamsArr [256]byte
	var sigParamsBuf []byte
	if sigParamsLen <= len(sigParamsArr) {
		sigParamsBuf = sigParamsArr[:0]
	} else {
		sigParamsBuf = make([]byte, 0, sigParamsLen)
	}
	sigParamsBuf = append(sigParamsBuf, `("@method" "@path" "content-digest");keyid="`...)
	sigParamsBuf = append(sigParamsBuf, did...)
	sigParamsBuf = append(sigParamsBuf, `";alg="ed25519";created=`...)
	sigParamsBuf = append(sigParamsBuf, createdBytes...)

	// Format signatureInput ("sig1=" + sigParamsBuf) in a single string allocation
	var sigInputArr [300]byte
	var sigInputBuf []byte
	sigInputLen := 5 + len(sigParamsBuf)
	if sigInputLen <= len(sigInputArr) {
		sigInputBuf = sigInputArr[:0]
	} else {
		sigInputBuf = make([]byte, 0, sigInputLen)
	}
	sigInputBuf = append(sigInputBuf, "sig1="...)
	sigInputBuf = append(sigInputBuf, sigParamsBuf...)
	signatureInput = string(sigInputBuf)

	methodUpper := toUpperASCII(method)

	// RFC 9421 Signing payload construction directly into byte buffer
	payloadLen := 11 + len(methodUpper) + 10 + len(pathAndQuery) + 19 + len(contentDigest) + 22 + len(sigParamsBuf)
	var payloadArr [512]byte
	var payload []byte
	if payloadLen <= len(payloadArr) {
		payload = payloadArr[:0]
	} else {
		payload = make([]byte, 0, payloadLen)
	}
	payload = append(payload, `"@method": `...)
	payload = append(payload, methodUpper...)
	payload = append(payload, "\n\"@path\": "...)
	payload = append(payload, pathAndQuery...)
	payload = append(payload, "\n\"content-digest\": "...)
	payload = append(payload, contentDigest...)
	payload = append(payload, "\n\"@signature-params\": "...)
	payload = append(payload, sigParamsBuf...)

	sigBytes := keypair.Sign(payload)

	var sigBuf [95]byte
	copy(sigBuf[:6], "sig1=:")
	base64.StdEncoding.Encode(sigBuf[6:94], sigBytes)
	sigBuf[94] = ':'
	signature = string(sigBuf[:])

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
	total := 0
	for _, b := range data {
		if b == 0 {
			total += 8
		} else {
			// Optimized using math/bits.LeadingZeros8 for fast hardware-accelerated bit counting.
			total += bits.LeadingZeros8(b)
			return total
		}
	}
	return total
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
