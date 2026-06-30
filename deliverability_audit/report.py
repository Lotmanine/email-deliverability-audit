"""Scoring + report rendering.

Score starts at 100 and each finding deducts a weight by severity. The result
is a letter grade plus a severity-bucketed list of findings, which mirrors how
I deliver deliverability audits to clients.
"""

from __future__ import annotations

from .checks import CRITICAL, FAIL, HIGH, INFO, LOW, MEDIUM, PASS, WARN, Finding

_WEIGHT = {CRITICAL: 40, HIGH: 20, MEDIUM: 10, LOW: 4, INFO: 0}
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


def score(findings: list[Finding]) -> int:
    penalty = sum(_WEIGHT[f.severity] for f in findings if f.status != PASS)
    return max(0, 100 - penalty)


def grade(value: int) -> str:
    return ("A" if value >= 90 else "B" if value >= 75 else
            "C" if value >= 60 else "D" if value >= 40 else "F")


def render(domain: str, findings: list[Finding]) -> str:
    value = score(findings)
    lines = [
        f"DELIVERABILITY AUDIT  -  {domain}",
        "=" * 48,
        f"Score: {value}/100   Grade: {grade(value)}",
        "",
    ]
    symbol = {PASS: "[ok]  ", WARN: "[warn]", FAIL: "[FAIL]"}
    for f in sorted(findings, key=lambda x: _ORDER[x.severity]):
        lines.append(f"{symbol[f.status]} {f.check:<6} ({f.severity}): {f.message}")
        if f.recommendation:
            lines.append(f"         -> {f.recommendation}")
    return "\n".join(lines)
