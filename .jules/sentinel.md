## 2025-05-18 - Validate Git Command Parameters Against Option Injection
**Vulnerability:** Untrusted user inputs like repository `source`, `destDir`, or `branch` passed to `exec.Command("git", ...)` enabled Git option injection (e.g. `--upload-pack` leading to arbitrary command execution).
**Learning:** `git clone` interprets positional arguments starting with `-` as CLI options unless validated and separated with `--`.
**Prevention:** Validate that input parameters do not start with `-` and pass `--` before positional arguments in `exec.Command`.

## 2025-05-18 - Validate Untrusted Response Header URLs Before Outbound Requests
**Vulnerability:** Untrusted HTTP response headers (such as `x-icaptcha-url`) returned by remote nodes were used directly in client HTTP POST calls without scheme or host validation, enabling SSRF and unencrypted credential transmission over plain HTTP.
**Learning:** Naive string prefix checks like `strings.HasPrefix(hostname, "127.")` are unsafe for loopback checks because domains like `127.0.0.1.attacker.com` match the prefix.
**Prevention:** Parse URLs with `url.Parse`, check the scheme (`https`), and use `net.ParseIP` + `ip.IsLoopback()` for loopback address checks.
