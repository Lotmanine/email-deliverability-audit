"""Live DNS lookups (the only part that touches the network).

Isolated behind a tiny interface so the pure checks in checks.py never import
dnspython and can be tested offline.
"""

from __future__ import annotations


class DnsResolver:
    """Thin wrapper around dnspython. Returns lists of strings, never raises
    on NXDOMAIN/timeout - an absent record is an empty list, which the checks
    interpret as 'not configured'."""

    def __init__(self, lifetime: float = 5.0):
        import dns.resolver  # imported lazily so the package imports without the dep
        self._dns = dns.resolver
        self._lifetime = lifetime

    def _txt(self, name: str) -> list[str]:
        try:
            answers = self._dns.resolve(name, "TXT", lifetime=self._lifetime)
        except Exception:
            return []
        out = []
        for rdata in answers:
            # join the chunked strings of a TXT record into one
            out.append("".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings))
        return out

    def txt(self, domain: str) -> list[str]:
        return self._txt(domain)

    def dmarc(self, domain: str) -> list[str]:
        return self._txt(f"_dmarc.{domain}")

    def dkim(self, domain: str, selector: str) -> list[str]:
        return self._txt(f"{selector}._domainkey.{domain}")

    def mx(self, domain: str) -> list[str]:
        try:
            answers = self._dns.resolve(domain, "MX", lifetime=self._lifetime)
        except Exception:
            return []
        return [str(r.exchange).rstrip(".") for r in answers]
