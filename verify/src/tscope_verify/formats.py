"""On-disk format identifiers shared by the product and the verifier (the verifier is the reference)."""

REPORT_SCHEMA = "tripline.report/v1"
RELEASE_SCHEMA = "tripline.release/v1"
SIGNATURES_SCHEMA = "tripline.signatures/v1"
CERTIFICATE_SCHEMA = "tripline.destruction-certificate/v1"
AUDIT_SCHEMA = "tripline.audit/v1"

REPORT_FILE = "report.json"
RELEASE_FILE = "release.json"
SIGNATURES_FILE = "signatures.json"
CERTIFICATE_FILE = "certificate.json"
CERTIFICATE_SIG_FILE = "certificate.sig.json"

GENESIS_HASH = "0" * 64

ROLE_HOSPITAL = "hospital"
ROLE_PROVIDER = "provider"
ROLE_RELEASE = "release"


def version_dirname(version: int) -> str:
    return f"v{version:04d}"
