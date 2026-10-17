"""Model-neutral provider interface. Explicit selection only; never an automatic fallback.

* ``fixture`` — deterministic rule-based output (:mod:`.fixture`); ``is_model_inference: false``.
* ``local`` — an OpenAI-compatible ``/v1/chat/completions`` server (for example llama.cpp ``llama-server`` or vLLM)
  that the hospital runs itself, configured by the administrator in ``config.yaml``::

      investigator:
        local:
          endpoint: http://127.0.0.1:8080/v1/chat/completions   # literal loopback address only
          model_id: <the served model's name>
          model_version: <version or weights hash, recorded in provenance>
          timeout_s: 120          # 5..600
          max_output_tokens: 4096

  The connection goes straight to the loopback literal with ``http.client``: no DNS, no proxies (environment proxy
  variables are ignored), no redirects, bounded request/response sizes and a hard timeout. Tripline never
  downloads weights, dependencies or extensions.
* ``openai-daybreak``, ``anthropic`` — adapter boundaries for future, separately approved integrations. In this
  release they are not authorised: they always report ``unavailable`` and make no connection. No API names, model
  ids or endpoints are assumed.
* The synthetic-only manual bridge is not a provider here: see ``run.bridge_export`` / ``run.bridge_import``.
"""

from __future__ import annotations

import http.client
import json
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from tripline_scope.core.errors import ConfigError, TriplineError

from . import fixture

LOOPBACK = {"127.0.0.1": "127.0.0.1", "localhost": "127.0.0.1", "::1": "::1", "[::1]": "::1"}
MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 1024 * 1024


class ProviderUnavailable(TriplineError):
    exit_code = 8


class ProviderFailed(TriplineError):
    exit_code = 8


@dataclass
class Budget:
    timeout_s: float = 120.0
    max_output_tokens: int = 4096
    max_request_bytes: int = MAX_REQUEST
    max_response_bytes: int = MAX_RESPONSE


@dataclass
class ProviderResponse:
    raw: bytes
    provenance: dict


class Provider:
    name = ""
    kind = ""

    def available(self) -> tuple[bool, str]:
        raise NotImplementedError

    def budget(self) -> Budget:
        return Budget()

    def analyse(self, prompt: dict, *, bundle: dict, budget: Budget) -> ProviderResponse:
        raise NotImplementedError


class FixtureProvider(Provider):
    name, kind = "fixture", "fixture"

    def available(self):
        return True, "deterministic fixture (not AI inference)"

    def analyse(self, prompt, *, bundle, budget):
        return ProviderResponse(fixture.output(bundle), {
            "provider": self.name, "provider_kind": "fixture", "model_id": fixture.FIXTURE_MODEL_ID,
            "model_version": fixture.FIXTURE_VERSION, "is_model_inference": False, "endpoint_class": "none",
            "notice": "Deterministic rule-based fixture output. This is not AI inference and says nothing about the "
                      "quality of any model."})


def _loopback_endpoint(url: str) -> tuple[str, int, str]:
    try:
        u = urlsplit(url)
    except ValueError as exc:
        raise ConfigError("investigator.local.endpoint is not a URL") from exc
    if u.scheme != "http" or u.username or u.password or u.query or u.fragment:
        raise ConfigError("investigator.local.endpoint must be a plain http:// URL on a loopback address")
    host = (u.hostname or "").lower()
    target = LOOPBACK.get(host) or LOOPBACK.get(f"[{host}]")
    if target is None:
        raise ConfigError("investigator.local.endpoint must use a literal loopback address (127.0.0.1, ::1 or localhost)")
    port = u.port or 80
    path = u.path or "/v1/chat/completions"
    return target, port, path


class LocalHTTPProvider(Provider):
    name, kind = "local", "local"

    def __init__(self, cfg: dict | None):
        self.cfg = dict(cfg or {})

    def available(self):
        if not self.cfg.get("endpoint") or not self.cfg.get("model_id"):
            return False, "no local model configured (config.yaml investigator.local: endpoint, model_id)"
        try:
            _loopback_endpoint(str(self.cfg["endpoint"]))
        except ConfigError as exc:
            return False, str(exc)
        return True, "local loopback model endpoint configured"

    def budget(self):
        t = float(self.cfg.get("timeout_s", 120))
        return Budget(timeout_s=min(max(t, 5.0), 600.0), max_output_tokens=int(min(max(int(self.cfg.get("max_output_tokens", 4096)), 256), 16384)))

    def analyse(self, prompt, *, bundle, budget):
        ok, why = self.available()
        if not ok:
            raise ProviderUnavailable(why)
        host, port, path = _loopback_endpoint(str(self.cfg["endpoint"]))
        req = {"model": str(self.cfg["model_id"]), "messages": prompt["messages"], "temperature": 0,
               "max_tokens": budget.max_output_tokens, "stream": False, "response_format": {"type": "json_object"}}
        if self.cfg.get("seed") is not None:
            req["seed"] = int(self.cfg["seed"])
        body = json.dumps(req).encode("utf-8")
        if len(body) > budget.max_request_bytes:
            raise ProviderFailed("prompt exceeds the request budget")
        deadline = time.monotonic() + budget.timeout_s
        conn = http.client.HTTPConnection(host, port, timeout=budget.timeout_s)
        try:
            conn.request("POST", path, body=body, headers={"Content-Type": "application/json", "Host": f"{host}:{port}",
                                                           "Accept": "application/json"})
            resp = conn.getresponse()
            if resp.status != 200:
                raise ProviderFailed(f"local model endpoint returned HTTP {resp.status}")
            data = resp.read(budget.max_response_bytes + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise ProviderFailed(f"local model endpoint unreachable or failed ({type(exc).__name__})") from None
        finally:
            conn.close()
        if time.monotonic() > deadline:
            raise ProviderFailed("local model exceeded the time budget")
        if len(data) > budget.max_response_bytes:
            raise ProviderFailed("local model response exceeds the size budget")
        try:
            doc = json.loads(data)
            content = doc["choices"][0]["message"]["content"]
            served = str(doc.get("model") or "")[:120]
        except (ValueError, KeyError, IndexError, TypeError):
            raise ProviderFailed("local model response is not an OpenAI-compatible chat completion") from None
        if not isinstance(content, str):
            raise ProviderFailed("local model returned no text content")
        return ProviderResponse(content.encode("utf-8"), {
            "provider": self.name, "provider_kind": "local", "model_id": str(self.cfg["model_id"])[:120],
            "model_version": str(self.cfg.get("model_version") or "not recorded")[:120], "served_model": served,
            "is_model_inference": True, "endpoint_class": "loopback"})


class HostedAdapter(Provider):
    """Boundary for a future hosted integration. Not authorised in this release: never connects."""

    kind = "hosted"

    def __init__(self, name: str):
        self.name = name

    def available(self):
        return False, (f"{self.name}: not authorised. No hosted model provider is enabled in this release; hospital "
                       "cases never send evidence to external services. A future integration needs a separate approval, "
                       "a contract that permits it, and an explicit change to this adapter.")

    def analyse(self, prompt, *, bundle, budget):
        raise ProviderUnavailable(self.available()[1])


HOSTED = ("openai-daybreak", "anthropic")


def get(name: str, home) -> Provider:
    cfg = (home.config.get("investigator") or {}) if home is not None else {}
    if name == "fixture":
        return FixtureProvider()
    if name == "local":
        return LocalHTTPProvider(cfg.get("local"))
    if name in HOSTED:
        return HostedAdapter(name)
    raise ConfigError(f"unknown provider {name!r} (choose: fixture, local, {', '.join(HOSTED)})")


def list_all(home) -> list[dict]:
    out = []
    for n in ("fixture", "local", *HOSTED):
        p = get(n, home)
        ok, why = p.available()
        out.append({"provider": n, "kind": p.kind, "available": ok, "detail": why})
    return out
