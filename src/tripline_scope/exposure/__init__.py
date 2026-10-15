"""Module A: exposure scan (readiness, offline).

A configuration and data-exposure assessment of hospital-authorised, read-only snapshots and exports. It is not a
vulnerability scanner or a penetration test: nothing here connects to production, validates credentials, probes
the network, deletes files or revokes access. See ``docs/EXPOSURE.md``.

Control families: A1 plaintext secrets, A2 excessive privileges, A3 uncontrolled patient-data copies, A4 risky
database configuration, A5 supplier access.
"""

# Version of the exposure method (detectors, severity model, report schema). Recorded in every report; bumped
# whenever a change could alter a finding, its id, its severity or the report layout.
METHOD_VERSION = "exposure-method/0.1.0"
DETECTOR_VERSION = "tscope-exposure/0.1.0"
REPORT_SCHEMA_VARIANT = "tripline.exposure-report/v1"
