"""The local provider against a stand-in OpenAI-compatible server on 127.0.0.1.

The stand-in answers with the deterministic fixture output, so these tests prove the transport, limits and safety
properties of the integration only. They say nothing about the quality of any real model (none is run here).
"""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

from conftest import cli, store_of
from tripline_scope.investigator import fixture as F
from tripline_scope.investigator import storage as S


class Stub:
    def __init__(self, mode="ok"):
        self.mode, self.requests = mode, []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                stub.requests.append({"path": self.path, "body": body, "host": self.headers.get("Host")})
                if stub.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://198.51.100.7/steal")
                    self.end_headers()
                    return
                if stub.mode == "slow":
                    time.sleep(7)
                if stub.mode == "huge":
                    data = b"{" + b" " * (2 * 1024 * 1024) + b"}"
                elif stub.mode == "garbage":
                    data = b"<html>not json</html>"
                else:
                    bundle = json.loads(body["messages"][1]["content"])["evidence_bundle_untrusted_data"]
                    content = F.output(bundle).decode() if stub.mode == "ok" else "I cannot help with that."
                    data = json.dumps({"model": "stub-model-q4", "choices": [{"message": {"role": "assistant",
                                                                                          "content": content}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def _configure(ns, **local):
    p = ns.env.home_dir / "config.yaml"
    cfg = yaml.safe_load(p.read_text())
    cfg["investigator"] = {"local": local}
    p.write_text(yaml.safe_dump(cfg, sort_keys=False))


@pytest.fixture
def stub():
    s = Stub()
    yield s
    s.close()


def _record_connections(monkeypatch):
    seen = []
    real = socket.socket.connect

    def connect(self, addr):
        seen.append(addr[0])
        return real(self, addr)

    monkeypatch.setattr(socket.socket, "connect", connect)
    return seen


def test_local_model_round_trip_loopback_only(cloned, stub, monkeypatch):
    _configure(cloned, endpoint=f"http://127.0.0.1:{stub.port}/v1/chat/completions", model_id="stub-model",
               model_version="q4-sha256-test", timeout_s=30)
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(k, "http://203.0.113.50:3128")       # environment proxies must be ignored
    seen = _record_connections(monkeypatch)
    rc, out, err = cli(["investigator", "analyse", *cloned.c, "--provider", "local"], "olivia")
    assert out["analysis_status"] == "completed" and out["provider_kind"] == "local" and out["is_model_inference"] is True
    assert set(seen) == {"127.0.0.1"}
    req = stub.requests[0]
    assert req["path"] == "/v1/chat/completions" and req["body"]["temperature"] == 0
    assert req["body"]["model"] == "stub-model" and [m["role"] for m in req["body"]["messages"]] == ["system", "user"]
    _, store = store_of(cloned.case_dir)
    res = S.load_result(store, out["run_id"])
    assert res["provenance"]["model_version"] == "q4-sha256-test" and res["provenance"]["served_model"] == "stub-model-q4"
    assert res["provenance"]["endpoint_class"] == "loopback"


@pytest.mark.parametrize("endpoint", ["http://10.1.2.3:8080/v1/chat/completions", "http://example.com/v1/chat/completions",
                                      "https://127.0.0.1:8443/v1/chat/completions", "http://u:p@127.0.0.1:9/v1",
                                      "http://127.0.0.1.nip.io/v1", "file:///etc/passwd"])
def test_non_loopback_endpoints_refused_without_connecting(cloned, monkeypatch, endpoint):
    _configure(cloned, endpoint=endpoint, model_id="m")
    seen = _record_connections(monkeypatch)
    rc, out, err = cli(["investigator", "analyse", *cloned.c, "--provider", "local"], "olivia", ok=False)
    assert rc == 8 and out["analysis_status"] == "unavailable" and seen == []


@pytest.mark.parametrize("mode,why", [("redirect", "HTTP 302"), ("huge", "size budget"), ("garbage", "not an OpenAI"),
                                      ("refuse", "rejected by the validator")])
def test_bad_local_responses_fail_closed(cloned, monkeypatch, mode, why):
    s = Stub(mode)
    try:
        _configure(cloned, endpoint=f"http://127.0.0.1:{s.port}/v1/chat/completions", model_id="m", timeout_s=30)
        seen = _record_connections(monkeypatch)
        rc, out, err = cli(["investigator", "analyse", *cloned.c, "--provider", "local"], "olivia", ok=False)
        assert rc == 8 and out["analysis_status"] == "failed" and why in out["status_reason"]
        assert set(seen) <= {"127.0.0.1"}
        if mode == "redirect":
            assert len(s.requests) == 1          # the redirect was not followed
    finally:
        s.close()


def test_timeout_and_unreachable(cloned):
    s = Stub("slow")
    try:
        _configure(cloned, endpoint=f"http://127.0.0.1:{s.port}/v1/chat/completions", model_id="m", timeout_s=5)
        t0 = time.time()
        rc, out, _ = cli(["investigator", "analyse", *cloned.c, "--provider", "local"], "olivia", ok=False)
        assert rc == 8 and out["analysis_status"] == "failed" and time.time() - t0 < 30
    finally:
        s.close()
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        dead = sk.getsockname()[1]
    _configure(cloned, endpoint=f"http://127.0.0.1:{dead}/v1/chat/completions", model_id="m", timeout_s=5)
    rc, out, _ = cli(["investigator", "analyse", *cloned.c, "--provider", "local"], "olivia", ok=False)
    assert rc == 8 and "unreachable" in out["status_reason"]
