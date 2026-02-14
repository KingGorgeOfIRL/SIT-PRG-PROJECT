import unittest
from unittest.mock import patch

from EmailVerify.main import EmailVerifier


# ---------------- INIT TEST ---------------- #

class TestEmailVerifierInit(unittest.TestCase):

    def test_init_basic(self):
        fake_email = type("Email", (), {})()
        fake_email.sender = "test@example.com"
        fake_email.headers = {}

        verifier = EmailVerifier(fake_email)

        self.assertEqual(verifier.risk_score, 0)
        self.assertEqual(verifier.flags, {})
        self.assertTrue(len(verifier.trusted_domains) > 0)
        self.assertTrue(len(verifier.known_company) > 0)


# ---------------- DOMAIN WHITELIST ---------------- #

class TestDomainWhitelistCheck(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "user@gmail.com"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)
        self.v.sender_domain = "gmail.com"

    def test_whitelisted_domain(self):
        self.v.domain_whitelist_check()

        self.assertTrue(self.v.flags.get("whitelisted_domain"))
        self.assertLess(self.v.risk_score, 0)


# ---------------- LOOKALIKE DOMAIN ---------------- #

class TestLookalikeDomain(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "support@paypa1.com"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)
        self.v.sender_domain = "paypa1.com"
        self.v.trusted_domains = {"paypal.com"}

    def test_lookalike_trigger(self):
        self.v.lookalike_domain_check()

        self.assertTrue(self.v.flags.get("lookalike_domain"))
        self.assertGreaterEqual(self.v.risk_score, 5)


# ---------------- BRAND IMPERSONATION ---------------- #

class TestBrandImpersonation(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "secure@paypal-secure-login.com"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)
        self.v.sender_domain = "paypal-secure-login.com"
        self.v.known_company = {"paypal"}
        self.v.trusted_domains = {"paypal.com"}

    def test_brand_in_domain(self):
        self.v.brand_in_domain_check()

        self.assertTrue(self.v.flags.get("brand_impersonation"))
        self.assertGreater(self.v.risk_score, 0)


# ---------------- SUSPICIOUS DOMAIN STRUCTURE ---------------- #

class TestSuspiciousDomainStructure(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "user@a.b.c.d.evil.com"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)
        self.v.sender_domain = "a.b.c.d.evil.com"

    def test_deep_subdomain(self):
        self.v.suspicious_domain_structure_check()

        self.assertTrue(self.v.flags.get("suspicious_domain_structure"))


# ---------------- NUMERIC USERNAME ---------------- #

class TestNumericUsername(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "user123456789@spam.com"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)
        self.v.sender_email = "user123456789@spam.com"

    def test_numeric_username_trigger(self):
        self.v.numeric_username_check()

        self.assertTrue(self.v.flags.get("numeric_username"))
        self.assertGreater(self.v.risk_score, 0)


# ---------------- RANDOM USERNAME ---------------- #

class TestRandomUsername(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "xj92ksla09238jdks123@spam.com"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)
        self.v.sender_email = "xj92ksla09238jdks123@spam.com"

    def test_random_username_trigger(self):
        self.v.random_username_check()

        self.assertTrue(self.v.flags.get("random_username"))
        self.assertGreater(self.v.risk_score, 0)


# ---------------- ALL CAPS DISPLAY NAME ---------------- #

class TestAllCapsDisplayName(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "DR MARKUS PHILLIPS <dr@company.com>"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)
        self.v.display_name = "DR MARKUS PHILLIPS"

    def test_all_caps_display_name_trigger(self):
        self.v.all_caps_display_name_check()

        self.assertTrue(self.v.flags.get("all_caps_display_name"))
        self.assertGreater(self.v.risk_score, 0)


# ---------------- MULTIPLE SENDERS ---------------- #

class TestMultipleSenders(unittest.TestCase):

    def setUp(self):
        self.fake_email = type("Email", (), {})()
        self.fake_email.sender = "a@test.com, b@test.com"
        self.fake_email.headers = {}

        self.v = EmailVerifier(self.fake_email)

    def test_multiple_senders_trigger(self):
        self.v.multiple_senders_check()

        self.assertTrue(self.v.flags.get("multiple_senders"))
        self.assertGreater(self.v.risk_score, 0)

# ---------------- RISK PERCENTAGE ---------------- #

class TestRiskPercentage(unittest.TestCase):

    def test_caps_at_100(self):
        fake_email = type("Email", (), {})()
        fake_email.sender = "support@paypa1.com"
        fake_email.headers = {}

        v = EmailVerifier(fake_email)
        v.risk_score = 999
        v.max_risk_score = 20

        percent = v.get_risk_percentage()
        self.assertEqual(percent, 100.0)


# ---------------- FINAL RESULT ---------------- #

class TestFinalResult(unittest.TestCase):

    def test_final_result_format(self):
        fake_email = type("Email", (), {})()
        fake_email.sender = "test@test.com"
        fake_email.headers = {}

        v = EmailVerifier(fake_email)
        v.risk_score = 5
        v.max_risk_score = 20

        result = v._final_result()

        self.assertIn("risk_score", result)
        self.assertIn("risk_percentage", result)
        self.assertIn("flags", result)


if __name__ == "__main__":
    unittest.main()
