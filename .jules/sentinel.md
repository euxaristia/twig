## 2025-05-22 - Normalize UCAN Token Slices and Prevent Filesystem Probing on JSON Input
**Vulnerability:** `ucan.Decode()` executed `os.Stat()` on raw token input before checking if it was JSON text, allowing raw JSON token strings to trigger filesystem syscalls. Additionally, unmarshaling tokens with omitted/null `prf` or `att` fields caused `VerifySignature()` to serialize them as `null` rather than `[]`, invalidating legitimate signatures.
**Learning:** Functions accepting both inline JSON and file paths must check for leading JSON indicators (`{` or `[`) before attempting file system lookups. Cryptographic signature verification over structs must normalize `nil` slice fields to empty non-nil slices before re-marshaling JSON.
**Prevention:** Always check prefix for JSON structures before file operations, and ensure nil slice fields are normalized before signature verification.
## 2025-05-22 - Prevent Integer Overflow Panics in EVM ABI Decoding
**Vulnerability:** Bounds checks structured as `len(data) < offset+32` in EVM ABI decoding functions allowed integer overflow when untrusted RPC data provided large offset values (e.g. `0x7fffffffffffffff - 10`), resulting in slice out-of-bounds panics and Denial of Service.
**Learning:** Checking `len(data) < offset + N` causes signed integer overflow when `offset` is large, evaluating to `true` on overflow and bypassing safety checks before slicing `data[offset:offset+32]`.
**Prevention:** Always write bounds checks using subtraction (`offset < 0 || offset > len(data)-N`) instead of adding offset and width together.

## 2025-05-21 - Escape Dynamic URL Path Parameters in CLI API Requests
**Vulnerability:** Dynamic path parameters (`owner`, `name`, `issueID`, `certID`, `bountyID`, `taskID`, `targetDID`, `cid`) formatted directly into HTTP endpoint URLs in CLI commands enabled path traversal (`../`) and API route injection against remote node endpoints.
**Learning:** Even if the MCP server implementation applies URL path escaping, CLI command endpoints constructing raw Sprintf URL paths must also consistently apply `url.PathEscape` and `url.QueryEscape`.
**Prevention:** Always wrap dynamic URL path segments in `url.PathEscape` and query parameters in `url.QueryEscape` when building HTTP request paths.

## 2025-05-20 - Enforce Not-Before (`nbf`) Claim in UCAN Token Verification
**Vulnerability:** UCAN token verification in CLI and MCP handlers computed token validity as `sigErr == nil && !isExpired`, ignoring the `nbf` (not before) claim. Future-dated UCAN tokens were treated as currently valid authorization tokens.
**Learning:** Defining helper methods like `IsBeforeValid()` without wiring them into top-level `IsValid()` or handler validation logic creates a gap where time-bound security claims are silently ignored.
**Prevention:** Always encapsulate full token validity criteria in `token.IsValid()` and ensure all token-verifying endpoints invoke it.

## 2025-05-18 - Validate Git Command Parameters Against Option Injection
**Vulnerability:** Untrusted user inputs like repository `source`, `destDir`, or `branch` passed to `exec.Command("git", ...)` enabled Git option injection (e.g. `--upload-pack` leading to arbitrary command execution).
**Learning:** `git clone` interprets positional arguments starting with `-` as CLI options unless validated and separated with `--`.
**Prevention:** Validate that input parameters do not start with `-` and pass `--` before positional arguments in `exec.Command`.

## 2025-05-18 - Validate Untrusted Response Header URLs Before Outbound Requests
**Vulnerability:** Untrusted HTTP response headers (such as `x-icaptcha-url`) returned by remote nodes were used directly in client HTTP POST calls without scheme or host validation, enabling SSRF and unencrypted credential transmission over plain HTTP.
**Learning:** Naive string prefix checks like `strings.HasPrefix(hostname, "127.")` are unsafe for loopback checks because domains like `127.0.0.1.attacker.com` match the prefix.
**Prevention:** Parse URLs with `url.Parse`, check the scheme (`https`), and use `net.ParseIP` + `ip.IsLoopback()` for loopback address checks.
