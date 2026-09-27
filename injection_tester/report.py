"""Console summary plus JSON and Markdown reports."""

import json
from collections import defaultdict
from datetime import datetime, timezone

from .runner import attack_success_rate

LINE = "-" * 96


def _by_owasp(results, defense):
    groups = defaultdict(lambda: [0, 0])
    for r in results:
        if r.defense == defense:
            groups[r.payload["owasp"]][1] += 1
            groups[r.payload["owasp"]][0] += r.verdict == "VULNERABLE"
    return dict(sorted(groups.items()))


def print_console(results, model, defenses, trials):
    print()
    print(f"LLM Prompt Injection Test - model: {model} - {trials} trial(s) per payload")
    for defense in defenses:
        print(LINE)
        print(f"Defence mode: {defense.upper()}   "
              f"attack success rate: {attack_success_rate(results, defense):.0%}")
        print(LINE)
        for r in results:
            if r.defense != defense:
                continue
            p = r.payload
            print(f"{r.verdict:10} {r.successes}/{len(r.trials)}  {p['id']:7} {p['owasp']:11} {p['technique']}")
    print(LINE)
    if len(defenses) > 1:
        print("By OWASP category (payloads bypassed / total):")
        for owasp in sorted({r.payload["owasp"] for r in results}):
            cells = []
            for d in defenses:
                hit, total = _by_owasp(results, d).get(owasp, [0, 0])
                cells.append(f"{d}: {hit}/{total}")
            print(f"  {owasp:11} " + "   ".join(cells))
    print()


def to_dict(results, model, defenses, trials):
    return {
        "model": model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trials_per_payload": trials,
        "attack_success_rate": {d: attack_success_rate(results, d) for d in defenses},
        "results": [
            {
                "id": r.payload["id"], "owasp": r.payload["owasp"], "category": r.payload["category"],
                "technique": r.payload["technique"], "defense": r.defense, "verdict": r.verdict,
                "successes": r.successes, "trials": len(r.trials),
                "outputs": [{"verdict": t.verdict, "reason": t.reason, "output": t.output,
                             "seconds": round(t.seconds, 2)} for t in r.trials],
            }
            for r in results
        ],
    }


def write_json(results, model, defenses, trials, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(results, model, defenses, trials), fh, indent=2, ensure_ascii=False)


def write_markdown(results, model, defenses, trials, path):
    lines = [
        "# LLM Prompt Injection Test Report",
        "",
        f"Model: `{model}` | trials per payload: {trials} | "
        f"generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC",
        "",
        "| Defence mode | Attack success rate |",
        "|---|---|",
    ]
    lines += [f"| {d} | {attack_success_rate(results, d):.0%} |" for d in defenses]
    lines += ["", "| ID | OWASP | Technique | Defence | Verdict | Successful trials |", "|---|---|---|---|---|---|"]
    for r in results:
        p = r.payload
        lines.append(f"| {p['id']} | {p['owasp']} | {p['technique']} | {r.defense} | "
                     f"{r.verdict} | {r.successes}/{len(r.trials)} |")
    lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(chr(10).join(lines))
