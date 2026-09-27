"""Run every payload against every defence mode, several times each.

LLMs are non-deterministic: the same attack can fail 4 times and work on the
5th. So we repeat each attack (--trials) and report an attack success rate
(ASR) instead of a single yes/no.
"""

import time
from dataclasses import dataclass, field

from .detectors import RESISTED, UNCLEAR, VULNERABLE, evaluate
from .targets import build_target, new_canaries


@dataclass
class TrialResult:
    verdict: str
    reason: str
    output: str
    seconds: float


@dataclass
class PayloadResult:
    payload: dict
    defense: str
    trials: list = field(default_factory=list)

    @property
    def successes(self):
        return sum(t.verdict == VULNERABLE for t in self.trials)

    @property
    def unclear(self):
        return sum(t.verdict == UNCLEAR for t in self.trials)

    @property
    def success_rate(self):
        return self.successes / len(self.trials) if self.trials else 0.0

    @property
    def verdict(self):
        """Worst case wins: one successful trial means the defence can be bypassed."""
        if self.successes:
            return VULNERABLE
        if self.unclear:
            return UNCLEAR
        return RESISTED


def run(client, payloads, defenses=("baseline", "hardened"), trials=3, progress=None):
    secret, pii = new_canaries()  # same canaries for both modes -> fair comparison
    results = []
    for defense in defenses:
        target = build_target(defense, secret, pii)
        for p in payloads:
            pr = PayloadResult(p, defense)
            for _ in range(trials):
                start = time.monotonic()
                output = client.chat(target.build_messages(p["prompt"]))
                verdict, reason = evaluate(p["check"], output, target)
                pr.trials.append(TrialResult(verdict, reason, output, time.monotonic() - start))
            results.append(pr)
            if progress:
                progress(pr)
    return results


def attack_success_rate(results, defense):
    """Share of payloads that got through at least once, for one defence mode."""
    subset = [r for r in results if r.defense == defense]
    if not subset:
        return 0.0
    return sum(r.verdict == VULNERABLE for r in subset) / len(subset)
