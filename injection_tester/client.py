"""Talk to a local model through the Ollama HTTP API.

Uses only the standard library (urllib), so the tool has no dependencies.
Ollama must be running locally: https://ollama.com
"""

import json
import urllib.error
import urllib.request


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, model, host="http://localhost:11434", temperature=0.7, timeout=120):
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    def _post(self, path, body):
        req = urllib.request.Request(
            self.host + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise OllamaError(f"Ollama returned HTTP {e.code}: {e.read().decode(errors='replace')}") from e
        except urllib.error.URLError as e:
            raise OllamaError(f"Cannot reach Ollama at {self.host} - is 'ollama serve' running? ({e.reason})") from e

    def check_model(self):
        """Fail early with a clear message if the model is not pulled."""
        try:
            with urllib.request.urlopen(self.host + "/api/tags", timeout=10) as resp:
                names = [m["name"] for m in json.loads(resp.read().decode()).get("models", [])]
        except urllib.error.URLError as e:
            raise OllamaError(f"Cannot reach Ollama at {self.host} - is 'ollama serve' running? ({e.reason})") from e
        if not any(n == self.model or n.split(":")[0] == self.model for n in names):
            raise OllamaError(f"Model '{self.model}' not found. Run: ollama pull {self.model}")

    def chat(self, messages):
        body = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        return self._post("/api/chat", body)["message"]["content"]
