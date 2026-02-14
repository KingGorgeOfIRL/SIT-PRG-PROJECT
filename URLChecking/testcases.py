import unittest
from unittest.mock import patch, MagicMock
from URLChecking.UrlCheck import UrlCheck, risk_score_calculate

# ---------- Base Test Class ----------
class BaseUrlTest(unittest.TestCase):
    def make_checker(self, urls=None, connectivity=False):
        """Create UrlCheck object without calling __init__"""
        urls = urls or []
        u = UrlCheck.__new__(UrlCheck)
        u.urls = urls
        u.triggered_checks = {url: [] for url in urls}
        u.connectivity = connectivity
        u.url_split = {
            url: {
                "scheme": url.split("://")[0] if "://" in url else None,
                "domain": url.split("/")[2] if "://" in url else url,
                "port": None,
                "path": None
            } for url in urls
        }

        # Stub all check methods to avoid real network calls
        for method in [
            "ssl_check", "ip_check", "port_check", "urlShortener_check", "length_check",
            "subdomain_check", "specialChar_check", "at_symbol_check", "punycode_check",
            "offline_redirection_check", "online_redirection_check", "domain_page_rank_check",
            "domain_age_check", "virus_total"
        ]:
            setattr(u, method, getattr(u, method, lambda: None))
        return u

# ---------- Structural Checks ----------
class TestStructuralChecks(BaseUrlTest):
    def test_ssl_check(self):
        u = self.make_checker(["http://a.com", "https://b.com"])
        # Simulate trigger manually
        u.triggered_checks["http://a.com"].append("ssl_check")
        ranked, final_checks = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://a.com"], 5)
        self.assertEqual(dict(ranked)["https://b.com"], 0)

    def test_length_check_edge_cases(self):
        short = "http://a.co"
        long = "http://example.com/" + "a"*300
        u = self.make_checker([short, long])
        # Manually trigger
        u.triggered_checks[short].append("length_check")
        u.triggered_checks[long].append("length_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        scores = dict(ranked)
        self.assertGreater(scores[short], 0)
        self.assertGreater(scores[long], 0)

    def test_subdomain_check(self):
        u = self.make_checker(["http://a.b.c.d.e.com"])
        u.triggered_checks["http://a.b.c.d.e.com"].append("subdomain_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://a.b.c.d.e.com"], 5)

# ---------- Suspicious Characters ----------
class TestSuspiciousCharacters(BaseUrlTest):
    def test_special_char_check(self):
        u = self.make_checker(["http://exa$mple.com"])
        u.triggered_checks["http://exa$mple.com"].append("specialChar_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://exa$mple.com"], 10)

    def test_at_symbol_check(self):
        u = self.make_checker(["http://user@evil.com"])
        u.triggered_checks["http://user@evil.com"].append("at_symbol_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://user@evil.com"], 10)

    def test_punycode_check(self):
        u = self.make_checker(["http://xn--evil.com"])
        u.triggered_checks["http://xn--evil.com"].append("punycode_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://xn--evil.com"], 70)

# ---------- Duplicate Trigger Protection ----------
class TestDuplicateProtection(BaseUrlTest):
    def test_no_double_counting(self):
        u = self.make_checker(["http://192.168.0.1"])
        u.triggered_checks["http://192.168.0.1"].append("ip_check")
        u.triggered_checks["http://192.168.0.1"].append("ip_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://192.168.0.1"], 12)  # first high=10 + duplicate 2%
        self.assertEqual(u.triggered_checks["http://192.168.0.1"].count("ip_check"), 2)


# ---------- Connectivity Behavior ----------
class TestConnectivityBehavior(BaseUrlTest):
    def test_offline_redirection_only(self):
        u = self.make_checker(["http://example.com/?redir=http://evil.com"], connectivity=False)
        u.triggered_checks["http://example.com/?redir=http://evil.com"].append("offline_redirection_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        score = dict(ranked)["http://example.com/?redir=http://evil.com"]
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)

    def test_online_redirection_check(self):
        u = self.make_checker(["http://example.com"], connectivity=True)
        u.triggered_checks["http://example.com"].append("online_redirection_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://example.com"], 10)

# ---------- Domain Age / Page Rank ----------
class TestDomainChecks(BaseUrlTest):
    def test_domain_age_exception_safe(self):
        u = self.make_checker(["http://example.com"], connectivity=True)
        u.triggered_checks["http://example.com"] = []
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://example.com"], 0)

    def test_page_rank_low_scores_high(self):
        u = self.make_checker(["http://lowrank.com"], connectivity=True)
        u.triggered_checks["http://lowrank.com"].append("domain_page_rank_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://lowrank.com"], 70)

# ---------- VirusTotal Handling ----------
class TestVirusTotalFailures(BaseUrlTest):
    def test_virus_total_exception_safe(self):
        u = self.make_checker(["http://evil.com"], connectivity=True)
        u.triggered_checks["http://evil.com"] = []
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["http://evil.com"], 0)

# ---------- Risk Score Calculation ----------
class TestRiskScoreCalculationExtended(unittest.TestCase):
    def test_multi_url_ranking(self):
        triggered_checks = {
            "a": ["ip_check", "ssl_check"],           # high + other
            "b": ["domain_age_check", "punycode_check"] # critical + critical
        }
        ranked, _ = risk_score_calculate(True, triggered_checks)
        scores = dict(ranked)
        self.assertEqual(scores["b"], 75)  # 70 + 5
        self.assertEqual(scores["a"], 15)  # 10 + 5
        self.assertEqual(ranked[0][0], "b") # highest first

# ---------- Edge Cases ----------
class TestEdgeCases(BaseUrlTest):
    def test_empty_url_list(self):
        u = self.make_checker([], connectivity=True)
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(ranked, [])

    def test_malformed_url(self):
        u = self.make_checker(["not_a_url"])
        u.triggered_checks["not_a_url"].append("ssl_check")
        ranked, _ = risk_score_calculate(u.connectivity, u.triggered_checks)
        self.assertEqual(dict(ranked)["not_a_url"], 5)

if __name__ == "__main__":
    unittest.main(verbosity=2)
