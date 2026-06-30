# email-deliverability-audit

Checks a domain's email authentication posture (**SPF · DKIM · DMARC · MX**) and rolls the findings into a **scored, severity-bucketed report**. This is the pre-flight check I run before any cold-sending or CRM/ESP migration: if these records are wrong, nothing else about deliverability matters.

## Design

- **Pure checks, isolated DNS.** All the rules live in [`checks.py`](deliverability_audit/checks.py) as pure functions that take already-fetched records, so they are unit-tested **offline and deterministically**. Live DNS (`dnspython`) is the only networked part, isolated in [`resolver.py`](deliverability_audit/resolver.py).
- **Severity-weighted scoring.** Start at 100, deduct by severity (critical 40 / high 20 / medium 10 / low 4). Output a letter grade and findings grouped worst-first.

## What it flags

| Check | Examples it catches |
|---|---|
| **SPF** | missing record (critical), multiple records (RFC violation), `+all`/`?all` (anyone can spoof you), softfail `~all` vs hardfail `-all` |
| **DMARC** | no `_dmarc` record, `p=none` (monitoring only, not enforcing), missing `rua=` aggregate reporting, ramp guidance toward `p=reject` |
| **DKIM** | selector resolves to a key or not |
| **MX** | records present / absent |

## Run it

```bash
pip install -r requirements.txt
python -m deliverability_audit example.com --selector google
```

Example report (a domain with SPF softfail, DMARC at p=none, no DKIM key for the selector):

```
DELIVERABILITY AUDIT  -  acme-demo.com
================================================
Score: 76/100   Grade: B

[warn] DKIM   (medium): No DKIM record found for selector 'google'.
         -> Confirm the selector your ESP uses, then verify <selector>._domainkey.<domain> resolves to a key.
[warn] DMARC  (medium): DMARC at p=none (monitoring only, not enforcing). No rua aggregate-report address set.
         -> Ramp the policy toward p=reject once reports look clean. Add a rua= address so you receive aggregate reports.
[warn] SPF    (low): SPF present with softfail (~all).
         -> Move to -all once you have confirmed every legitimate sender is listed.
[ok]   MX     (info): 1 MX record(s) present.
```

## Tests

```bash
python -m unittest discover -s tests -t .
```

9 offline tests (no network) covering SPF/DMARC/DKIM rules and scoring.

## License

MIT.
