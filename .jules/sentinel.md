## 2026-10-04 - Enforce NBF (Not Before) Validation in UCAN Verification
**Vulnerability:** UCAN tokens containing future `nbf` (not before) activation timestamps were accepted as valid during `twig ucan verify` execution because `UcanVerify` only checked signature validity and expiration (`exp`).
**Learning:** Checking signature and expiration isn't sufficient when authorization specs include `nbf` claims; failing to check `nbf` allows premature usage of scheduled tokens.
**Prevention:** Always check both `exp` and `nbf` claims during token validation routines.
