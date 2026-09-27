"""Runner, payload library, targets, CLI and the real Ollama client (against a fake HTTP server)."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from injection_tester.client import OllamaClient, OllamaError
from injection_tester.payloads import load_payloads
from injection_tester.runner import attack_success_rate, run
from injection_tester.simulated import SimulatedModel
from injection_tester.targets import build_target


# ---------------- payload library ----------------

def test_library_loads_and_is_valid():
    payloads = load_payloads()
    assert len(payloads) == 15
    assert {p["owasp"] for p in payloads} == {"LLM01:2025", "LLM02:2025", "LLM05:2025", "LLM07:2025"}


def test_owasp_filter():
    assert all(p["owasp"].startswith("LLM07") for p in load_payloads(owasp_filter=["llm07"]))


def test_invalid_payload_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"id": "X", "prompt": "hi"}]))
    with pytest.raises(ValueError):
        load_payloads(bad)


# ---------------- targets ----------------

def test_hardened_target_wraps_user_input():
    msgs = build_target("hardened").build_messages("hello")
    assert msgs[1]["content"] == "<user_input>hello</user_input>"
    assert "Security rules" in msgs[0]["content"]


def test_canaries_are_random_per_target():
    assert build_target("baseline").secret_canary != build_target("baseline").secret_canary


# ---------------- runner ----------------

def test_hardening_reduces_attack_success_on_simulated_model():
    results = run(SimulatedModel(), load_payloads(), trials=1)
    assert attack_success_rate(results, "baseline") == 1.0
    assert attack_success_rate(results, "hardened") < 0.2


class FlakyModel:
    """Leaks on every second call - models the non-determinism of real LLMs."""
    model = "flaky"

    def __init__(self):
        self.calls = 0

    def chat(self, messages):
        self.calls += 1
        if self.calls % 2 == 0:
            return "INJECTION-OK"
        return "I can only help with opening hours and blocking a card."


def test_one_success_in_several_trials_marks_vulnerable():
    payload = [p for p in load_payloads() if p["id"] == "PI-01"]
    result = run(FlakyModel(), payload, defenses=["baseline"], trials=4)[0]
    assert result.successes == 2 and result.success_rate == 0.5
    assert result.verdict == "VULNERABLE"


# ---------------- Ollama client vs fake server ----------------

class FakeOllama(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"models": [{"name": "llama3.2:3b"}]})

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert req["stream"] is False and req["messages"][0]["role"] == "system"
        self._send({"message": {"role": "assistant", "content": "echo: " + req["messages"][1]["content"]}})


@pytest.fixture
def fake_ollama():
    server = HTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_client_chat_roundtrip(fake_ollama):
    client = OllamaClient("llama3.2:3b", fake_ollama)
    client.check_model()
    out = client.chat([{"role": "system", "content": "s"}, {"role": "user", "content": "hi"}])
    assert out == "echo: hi"


def test_client_reports_missing_model(fake_ollama):
    with pytest.raises(OllamaError, match="ollama pull mistral"):
        OllamaClient("mistral", fake_ollama).check_model()


def test_client_reports_ollama_not_running():
    with pytest.raises(OllamaError, match="ollama serve"):
        OllamaClient("llama3.2:3b", "http://127.0.0.1:9").check_model()


# ---------------- CLI end-to-end ----------------

def test_cli_demo_writes_reports(tmp_path, monkeypatch):
    import pit
    monkeypatch.setattr(sys, "argv", ["pit.py", "--demo", "--trials", "1",
                                      "--json", str(tmp_path / "r.json"), "--md", str(tmp_path / "r.md")])
    pit.main()
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["attack_success_rate"]["baseline"] == 1.0
    assert (tmp_path / "r.md").read_text().startswith("# LLM Prompt Injection Test Report")
