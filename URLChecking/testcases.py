import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from URLChecking.UrlCheck import UrlCheck, risk_score_calculate
from LangAnalysis import Email


class TestUrlDissection(unittest.TestCase):
    def setUp(self):
        self.urls = [
            "http://example.com/path",
            "https://example.com:8080/a/b",
            "example.com",
            "http://192.168.1.1/login"
        ]

        with patch.object(Email, "__init__", lambda x, y=None: None):
            self.u = UrlCheck(email_path=None)
            self.u.urls = self.urls
            self.u.url_score = {url: 0 for url in self.u.urls}
            self.u.triggered_checks = {url: [] for url in self.u.urls}
            self.u.url_split = self.u._UrlCheck__url_dissection()

    def test_scheme_domain_port_path(self):
        d = self.u.url_split["https://example.com:8080/a/b"]
        self.assertEqual(d["scheme"], "https")
        self.assertEqual(d["domain"], "example.com")
        self.assertEqual(d["port"], "8080")
        self.assertEqual(d["path"], "a/b")

    def test_ip_domain_detected(self):
        d = self.u.url_split["http://192.168.1.1/login"]
        self.assertEqual(d["domain"], "192.168.1.1")


class TestUrlChecksOffline(unittest.TestCase):
    def setUp(self):
        with patch.object(Email, "__init__", lambda x, y=None: None):
            self.u = UrlCheck(email_path=None)
            self.u.urls = [
                "http://192.168.0.1",
                "http://bit.ly/test",
                "http://example.com:1234/path?redir=http://evil.com",
            ]
            # Initialize after setting URLs
            self.u.url_score = {url: 0 for url in self.u.urls}
            self.u.triggered_checks = {url: [] for url in self.u.urls}
            self.u.url_split = self.u._UrlCheck__url_dissection()
            self.u.connectivity = False

    @patch.object(UrlCheck, "extract_wordlist", return_value=["80", "443"])
    def test_port_check(self, _):
        self.u.port_check()
        self.assertGreater(
            self.u.url_score["http://example.com:1234/path?redir=http://evil.com"], 0
        )

    def test_ip_check(self):
        self.u.ip_check()
        self.assertEqual(self.u.url_score["http://192.168.0.1"], 20)

    @patch.object(UrlCheck, "extract_wordlist", return_value=["bit.ly"])
    def test_url_shortener(self, _):
        self.u.urlShortener_check()
        self.assertEqual(self.u.url_score["http://bit.ly/test"], 10)

    @patch.object(UrlCheck, "extract_wordlist", return_value=["redir"])
    def test_offline_redirection(self, _):
        self.u.offline_redirection_check()
        self.assertEqual(
            self.u.url_score["http://example.com:1234/path?redir=http://evil.com"], 10
        )

class TestDomainAgeCheck(unittest.TestCase):
    def setUp(self):
        with patch("LangAnalysis.Email.__init__", lambda self, y=None: None):
            self.u = UrlCheck(email_path=None)
            self.u.urls = ["http://example.com"]
            self.u.url_score = {url: 0 for url in self.u.urls}
            self.u.triggered_checks = {url: [] for url in self.u.urls}
            self.u.url_split = self.u._UrlCheck__url_dissection()
            self.u.connectivity = True

    @patch("URLChecking.UrlCheck.get")
    def test_domain_age_check_young_domain(self, mock_get):
        # Mock RDAP API response with a recent registration date
        recent_date = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "events": [
                {"eventAction": "registration", "eventDate": recent_date}
            ]
        }

        self.u.domain_age_check()
        self.assertEqual(self.u.url_score["http://example.com"], 20)


class TestVirusTotal(unittest.TestCase):
    def setUp(self):
        with patch.object(Email, "__init__", lambda x, y=None: None):
            self.u = UrlCheck(email_path=None)
            self.u.urls = ["http://malicious.com"]
            self.u.url_score = {url: 0 for url in self.u.urls}
            self.u.triggered_checks = {url: [] for url in self.u.urls}
            self.u.url_split = self.u._UrlCheck__url_dissection()
            self.u.connectivity = True

    @patch("URLChecking.UrlCheck.post")  # patch post directly
    @patch("URLChecking.UrlCheck.get")   # patch get directly
    def test_virus_total_malicious(self, mock_get, mock_post):
        mock_post.return_value.json.return_value = {"data": {"id": "abc"}}

        mock_get.return_value.json.return_value = {
            "data": {"attributes": {"stats": {"malicious": 5, "harmless": 0}}}
        }

        self.u.virus_total()
        self.assertEqual(self.u.url_score["http://malicious.com"], 50)


class TestRiskScoreCalculation(unittest.TestCase):
    def test_risk_score_online(self):
        scores = {"a": 140}
        max_score = 280  # example max
        final, triggered, ranked = risk_score_calculate(max_score, scores, True, {"a":[]})
        self.assertEqual(final["a"], 50.0)

    def test_risk_score_offline(self):
        scores = {"a": 120}
        max_score = 240  # example max
        final, triggered, ranked = risk_score_calculate(max_score, scores, False, {"a":[]})
        self.assertEqual(final["a"], 50.0)


if __name__ == "__main__":
    unittest.main()
