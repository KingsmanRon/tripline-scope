"""Tripline Scope: breach scoping for South African hospitals and laboratories."""

import os as _os

__version__ = "0.1.0"
# Version of the scoping method (matching rules, bands, report schema). Bumped whenever a change could
# alter a count; recorded in every report.
METHOD_VERSION = "scope-method/0.1.0"

# No telemetry, ever: make sure no OpenTelemetry SDK that might be present in the environment exports.
_os.environ.setdefault("OTEL_SDK_DISABLED", "true")
_os.environ.setdefault("OTEL_TRACES_EXPORTER", "none")
_os.environ.setdefault("OTEL_METRICS_EXPORTER", "none")
_os.environ.setdefault("OTEL_LOGS_EXPORTER", "none")
