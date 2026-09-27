#!/usr/bin/env python3
"""
LLM Prompt Injection Tester
Runs a library of prompt injection attacks (OWASP Top 10 for LLM Applications
2025) against a locally hosted model and measures how often they succeed,
with and without prompt-level defences.

Usage:
  python3 pit.py --demo                              # no Ollama needed (simulated model)
  python3 pit.py --model llama3.2:3b                 # real local model via Ollama
  python3 pit.py --model mistral --trials 5 --md report.md --json report.json
  python3 pit.py --model llama3.2:3b --owasp LLM07 --defense baseline
"""

import argparse
import sys

from injection_tester import report
from injection_tester.client import OllamaClient, OllamaError
from injection_tester.payloads import load_payloads
from injection_tester.runner import run
from injection_tester.simulated import SimulatedModel


def main():
    parser = argparse.ArgumentParser(description="Automated prompt injection testing for local LLMs.")
    parser.add_argument("--model", help="Ollama model name, e.g. llama3.2:3b")
    parser.add_argument("--host", default="http://localhost:11434", help="Ollama API address")
    parser.add_argument("--demo", action="store_true", help="Use the scripted simulated model (no Ollama)")
    parser.add_argument("--trials", type=int, default=3, help="Repetitions per payload (default 3)")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--defense", choices=["baseline", "hardened", "both"], default="both")
    parser.add_argument("--owasp", nargs="+", help="Only run these categories, e.g. LLM01 LLM07")
    parser.add_argument("--payloads", help="Path to a custom payloads JSON file")
    parser.add_argument("--json", help="Write full results (including model outputs) to JSON")
    parser.add_argument("--md", help="Write a Markdown summary report")
    args = parser.parse_args()

    if not args.demo and not args.model:
        parser.error("give --model (Ollama) or --demo")
    if args.trials < 1:
        parser.error("--trials must be at least 1")

    client = SimulatedModel() if args.demo else OllamaClient(args.model, args.host, args.temperature)
    try:
        client.check_model()
    except OllamaError as e:
        sys.exit(str(e))

    payloads = load_payloads(args.payloads, args.owasp) if args.payloads else load_payloads(owasp_filter=args.owasp)
    if not payloads:
        sys.exit("No payloads match the filter.")
    defenses = ["baseline", "hardened"] if args.defense == "both" else [args.defense]

    total = len(payloads) * len(defenses)
    done = [0]

    def progress(result):
        done[0] += 1
        print(f"  [{done[0]}/{total}] {result.defense:8} {result.payload['id']:7} {result.verdict}", file=sys.stderr)

    try:
        results = run(client, payloads, defenses, args.trials, progress)
    except OllamaError as e:
        sys.exit(str(e))

    report.print_console(results, client.model, defenses, args.trials)
    if args.json:
        report.write_json(results, client.model, defenses, args.trials, args.json)
    if args.md:
        report.write_markdown(results, client.model, defenses, args.trials, args.md)


if __name__ == "__main__":
    main()
