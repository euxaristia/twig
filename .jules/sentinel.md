## 2025-05-20 - Enforce Not-Before (`nbf`) Claim in UCAN Token Verification
**Vulnerability:** UCAN token verification in CLI and MCP handlers computed token validity as `sigErr == nil && !isExpired`, ignoring the `nbf` (not before) claim. Future-dated UCAN tokens were treated as currently valid authorization tokens.
**Learning:** Defining helper methods like `IsBeforeValid()` without wiring them into top-level `IsValid()` or handler validation logic creates a gap where time-bound security claims are silently ignored.
**Prevention:** Always encapsulate full token validity criteria in `token.IsValid()` and ensure all token-verifying endpoints invoke it.

## 2025-05-18 - Validate Untrusted Response Header URLs Before Outbound Requests
**Vulnerability:** Untrusted HTTP response headers (such as `x-icaptcha-url`) returned by remote nodes were used directly in client HTTP POST calls without scheme or host validation, enabling SSRF and unencrypted credential transmission over plain HTTP.
**Learning:** Naive string prefix checks like `strings.HasPrefix(hostname, "127.")` are unsafe for loopback checks because domains like `127.0.0.1.attacker.com` match the prefix.
**Prevention:** Parse URLs with `url.Parse`, check the scheme (`https`), and use `net.ParseIP` + `ip.IsLoopback()` for loopback address checks.
