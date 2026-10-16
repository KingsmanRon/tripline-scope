# tripline-scope-verify

Stand-alone, offline verifier for artefacts produced by Tripline Scope. It depends only on
`cryptography` and `rfc8785` and does not need the rest of the product installed.

```
tscope-verify report  CASE_DIR/reports/scope/v0002 --hospital-key hospital.pub [--provider-key provider.pub]
tscope-verify chain   CASE_DIR/reports/scope        --hospital-key hospital.pub
tscope-verify audit   CASE_DIR/audit.log
tscope-verify certificate destruction-certificate.json --hospital-key hospital.pub
tscope-verify checksums SHA256SUMS --sig SHA256SUMS.sig --key release.pub
```

Exit status 0 means every check passed; 1 means at least one check failed; 2 means usage error.
Every signature is a plain Ed25519 signature over the exact bytes of a canonical (RFC 8785) JSON file,
so the same checks can be reproduced with OpenSSL (see `docs/SECURITY.md` in the main repository).
