"""    python -m deliverability_audit example.com --selector google"""

from __future__ import annotations

import argparse

from . import checks
from .report import render
from .resolver import DnsResolver


def audit(domain: str, selector: str, resolver) -> list[checks.Finding]:
    return [
        checks.check_spf(resolver.txt(domain)),
        checks.check_dkim(selector, resolver.dkim(domain, selector)),
        checks.check_dmarc(resolver.dmarc(domain)),
        checks.check_mx(resolver.mx(domain)),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a domain's email deliverability posture.")
    parser.add_argument("domain")
    parser.add_argument("--selector", default="default",
                        help="DKIM selector to check (e.g. google, k1, s1, dkim).")
    args = parser.parse_args(argv)

    try:
        resolver = DnsResolver()
    except ImportError:
        print("This tool needs dnspython for live lookups:  pip install dnspython")
        return 2

    findings = audit(args.domain, args.selector, resolver)
    print(render(args.domain, findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
