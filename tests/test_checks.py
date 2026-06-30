"""Offline tests: feed synthetic DNS records through the pure checks and the
scorer. No network, fully deterministic."""

import unittest

from deliverability_audit import checks
from deliverability_audit.cli import audit
from deliverability_audit.report import grade, render, score


class FakeResolver:
    """Stands in for DnsResolver with canned records."""

    def __init__(self, txt=None, dmarc=None, dkim=None, mx=None):
        self._txt, self._dmarc, self._dkim, self._mx = txt or [], dmarc or [], dkim or [], mx or []

    def txt(self, domain): return self._txt
    def dmarc(self, domain): return self._dmarc
    def dkim(self, domain, selector): return self._dkim
    def mx(self, domain): return self._mx


class TestSpf(unittest.TestCase):
    def test_missing_spf_is_critical_fail(self):
        f = checks.check_spf([])
        self.assertEqual((f.status, f.severity), (checks.FAIL, checks.CRITICAL))

    def test_hardfail_passes(self):
        f = checks.check_spf(["v=spf1 include:_spf.google.com -all"])
        self.assertEqual(f.status, checks.PASS)

    def test_plus_all_is_high_fail(self):
        f = checks.check_spf(["v=spf1 +all"])
        self.assertEqual((f.status, f.severity), (checks.FAIL, checks.HIGH))

    def test_multiple_records_fail(self):
        f = checks.check_spf(["v=spf1 -all", "v=spf1 ~all"])
        self.assertEqual(f.status, checks.FAIL)


class TestDmarc(unittest.TestCase):
    def test_none_is_warn(self):
        f = checks.check_dmarc(["v=DMARC1; p=none; rua=mailto:r@example.com"])
        self.assertEqual(f.status, checks.WARN)

    def test_reject_passes(self):
        f = checks.check_dmarc(["v=DMARC1; p=reject; rua=mailto:r@example.com"])
        self.assertEqual(f.status, checks.PASS)

    def test_missing_rua_is_recommended(self):
        f = checks.check_dmarc(["v=DMARC1; p=quarantine"])
        self.assertIn("rua", f.recommendation.lower())


class TestScoring(unittest.TestCase):
    def test_perfect_domain_scores_high(self):
        findings = audit("example.com", "google", FakeResolver(
            txt=["v=spf1 include:_spf.google.com -all"],
            dmarc=["v=DMARC1; p=reject; rua=mailto:r@example.com"],
            dkim=["v=DKIM1; k=rsa; p=MIGfMA0..."],
            mx=["aspmx.l.google.com"],
        ))
        self.assertGreaterEqual(score(findings), 90)
        self.assertEqual(grade(score(findings)), "A")

    def test_bare_domain_scores_low(self):
        findings = audit("example.com", "default", FakeResolver())
        self.assertLess(score(findings), 60)
        self.assertIn("FAIL", render("example.com", findings))


if __name__ == "__main__":
    unittest.main()
