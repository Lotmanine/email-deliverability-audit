"""Pure deliverability checks.

Each function takes the *raw DNS records* (already fetched) and returns a
Finding. Keeping the analysis pure (no network) means the rules are unit-tested
offline and deterministically, while live DNS lookups stay isolated in
resolver.py.
"""

from __future__ import annotations

from dataclasses import dataclass

# Severity ordering used for scoring and grouping.
CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"
PASS, WARN, FAIL = "pass", "warn", "fail"


@dataclass
class Finding:
    check: str
    status: str       # pass | warn | fail
    severity: str     # critical | high | medium | low | info
    message: str
    recommendation: str = ""


def check_mx(mx_records: list[str]) -> Finding:
    if not mx_records:
        return Finding("MX", FAIL, MEDIUM,
                       "No MX records found.",
                       "Add MX records if this domain should receive mail.")
    return Finding("MX", PASS, INFO, f"{len(mx_records)} MX record(s) present.")


def check_spf(txt_records: list[str]) -> Finding:
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf:
        return Finding("SPF", FAIL, CRITICAL,
                       "No SPF record (v=spf1) found.",
                       "Publish an SPF TXT record listing every service that sends as this domain, ending in ~all or -all.")
    if len(spf) > 1:
        return Finding("SPF", FAIL, HIGH,
                       "Multiple SPF records found (RFC 7208 allows only one).",
                       "Merge them into a single v=spf1 record.")
    record = spf[0].lower()
    if record.endswith("-all"):
        return Finding("SPF", PASS, INFO, "SPF present with hardfail (-all).")
    if record.endswith("~all"):
        return Finding("SPF", WARN, LOW,
                       "SPF present with softfail (~all).",
                       "Move to -all once you have confirmed every legitimate sender is listed.")
    if record.endswith("+all") or "?all" in record:
        return Finding("SPF", FAIL, HIGH,
                       "SPF ends with +all/?all, which authorizes anyone to send as you.",
                       "Change the qualifier to ~all or -all.")
    return Finding("SPF", WARN, MEDIUM,
                   "SPF present but has no explicit all mechanism.",
                   "Add a terminating ~all or -all.")


def check_dmarc(dmarc_txt: list[str]) -> Finding:
    dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return Finding("DMARC", FAIL, HIGH,
                       "No DMARC record at _dmarc.<domain>.",
                       "Publish v=DMARC1; start with p=none plus a rua address to collect reports, then ramp to quarantine/reject.")
    record = dmarc[0].lower()
    policy = _tag(record, "p") or "none"
    has_rua = "rua=" in record
    if policy == "reject":
        sev, status, msg = INFO, PASS, "DMARC enforced (p=reject)."
    elif policy == "quarantine":
        sev, status, msg = LOW, PASS, "DMARC at p=quarantine."
    else:
        sev, status, msg = MEDIUM, WARN, "DMARC at p=none (monitoring only, not enforcing)."
    rec = "" if policy == "reject" else "Ramp the policy toward p=reject once reports look clean."
    if not has_rua:
        msg += " No rua aggregate-report address set."
        rec = (rec + " Add a rua= address so you receive aggregate reports.").strip()
    return Finding("DMARC", status, sev, msg, rec)


def check_dkim(selector: str, dkim_txt: list[str]) -> Finding:
    dkim = [t for t in dkim_txt if "v=dkim1" in t.lower() or "p=" in t.lower()]
    if not dkim:
        return Finding("DKIM", WARN, MEDIUM,
                       f"No DKIM record found for selector '{selector}'.",
                       "Confirm the selector your ESP uses, then verify <selector>._domainkey.<domain> resolves to a key.")
    return Finding("DKIM", PASS, INFO, f"DKIM key present for selector '{selector}'.")


def _tag(record: str, tag: str) -> str:
    for part in record.split(";"):
        part = part.strip()
        if part.startswith(f"{tag}="):
            return part.split("=", 1)[1].strip()
    return ""
