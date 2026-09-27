"""Load and validate the attack library (payloads/payloads.json)."""

import json
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "payloads" / "payloads.json"
REQUIRED = ("id", "owasp", "category", "technique", "check", "prompt")
CHECKS = ("marker", "leak_secret", "leak_pii", "script_tag")


def load_payloads(path=DEFAULT_PATH, owasp_filter=None):
    with open(path, encoding="utf-8") as fh:
        payloads = json.load(fh)

    seen = set()
    for p in payloads:
        missing = [k for k in REQUIRED if k not in p]
        if missing:
            raise ValueError(f"payload {p.get('id', '?')} is missing fields: {missing}")
        if p["check"] not in CHECKS:
            raise ValueError(f"payload {p['id']} has unknown check '{p['check']}'")
        if p["id"] in seen:
            raise ValueError(f"duplicate payload id {p['id']}")
        seen.add(p["id"])

    if owasp_filter:
        wanted = {o.upper() for o in owasp_filter}
        payloads = [p for p in payloads if p["owasp"].split(":")[0].upper() in wanted]
    return payloads
