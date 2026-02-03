import os
import tempfile
import unittest
from unittest.mock import patch

# Replace this with the module name that contains your code
import main as m


class TestUtilities(unittest.TestCase):
    def test_safe_filename_sanitizes(self):
        self.assertEqual(m._safe_filename("../evil.txt"), "evil.txt")
        self.assertEqual(m._safe_filename(""), "attachment.bin")

    def test_extract_hrefs_from_html(self):
        html = '<a href="https://a.com">x</a> <a href=\'/path\'>y</a>'
        self.assertEqual(m._extract_hrefs_from_html(html), ["https://a.com", "/path"])

    def test_strip_tags(self):
        self.assertEqual(m._strip_tags("<p>Hello <b>World</b></p>").strip(), "Hello World")

class TestInitFile(unittest.TestCase):
    def test_init_file_dict_mode_parses_numbers(self):
        content = """
        # comment
        key1, 10
        key2 2.5
        malformed_line_only_key
        key3, not_a_number
        """
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "k.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)

            d = m.init_file(p)
            self.assertEqual(d["key1"], 10)
            self.assertEqual(d["key2"], 2.5)
            self.assertEqual(d["key3"], "not_a_number")
            self.assertNotIn("malformed_line_only_key", d)

    def test_init_file_list_mode(self):
        content = "a,1\nb,2\n"
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "k.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)

            lst = m.init_file(p, conv_to_list=True)
            self.assertEqual(lst, [["a", "1"], ["b", "2"]])

    def test_init_file_inverse(self):
        content = "word, 7\n"
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "k.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)

            d = m.init_file(p, inverse=True)
            # inverse maps str(value) -> key
            self.assertEqual(d["7"], "word")

class TestDetectProb(unittest.TestCase):
    def test_detect_prob_longest_match_first(self):
        keywords = {
            "please": 5.0,
            "process payment": 30.0,
            "process payment urgently": 60.0,
        }
        tokens = ["please", "process", "payment", "urgently", "now"]

        prob, freq = m.detect_prob(tokens, keywords, {})
        # should match "process payment urgently" (60) not the shorter one (30)
        self.assertEqual(prob, 5.0 + 60.0)
        self.assertEqual(freq["please"], 1)
        self.assertEqual(freq["process payment urgently"], 1)
        self.assertNotIn("process payment", freq)

    def test_detect_prob_no_match(self):
        keywords = {"bank": 10.0}
        tokens = ["hello", "there"]
        prob, freq = m.detect_prob(tokens, keywords, {})
        self.assertEqual(prob, 0.0)
        self.assertEqual(freq, {})

class TestConfidence(unittest.TestCase):
    def test_calc_confidence_ignores_low_counts(self):
        observed = {"bank": 3, "security": 10}
        model = {"bank": 50.0, "security": 50.0}
        # bank count=3 ignored, only security contributes
        total = 13
        observed_pct_security = (10 / total) * 100  # 76.923...
        expected_pct_security = 50.0
        expected_penalty = abs(expected_pct_security - observed_pct_security)
        self.assertAlmostEqual(m.calc_confidence(observed, model), expected_penalty, places=6)

    def test_calc_confidence_empty(self):
        self.assertEqual(m.calc_confidence({}, {"x": 1.0}), 0.0)

class TestEmailLanguageRisk(unittest.TestCase):
    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_language_risk_simple(self, _mock_lemma):
        # Minimal matrix: two flags
        matrix = {
            "finance": {"process payment": 100.0},
            "it": {"revalidate your mailbox": 100.0},
        }

        # Body contains one finance phrase once.
        # Keep title empty to avoid extra tokens.
        scores = m.email_language_risk(
            email=None,
            body="Please process payment now.",
            title="",
            matrix=matrix,
            total_weightage=40,
            base_confidence_score=100,
        )

        # total_weightage 40 / 2 flags = 20 per flag
        # finance should get > 0, it should be 0 (no match)
        self.assertIn("finance", scores)
        self.assertIn("it", scores)
        self.assertEqual(scores["it"], 0.0)

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_language_risk_raises_without_matrix(self, _mock_lemma):
        with self.assertRaises(ValueError):
            m.email_language_risk(body="x", title="y", matrix=None)

class TestEmailParsing(unittest.TestCase):
    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_parses_subject_sender_and_body(self, _mock_lemma):
        # A minimal EML with plain text body
        eml = (
            "From: Alice <alice@example.com>\r\n"
            "To: Bob <bob@example.com>\r\n"
            "Subject: Test Subject\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Hello world\r\n"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as td:
            eml_path = os.path.join(td, "msg.eml")
            with open(eml_path, "wb") as f:
                f.write(eml)

            e = m.Email(email_path=eml_path, attachment_output_path=os.path.join(td, "att"))
            self.assertEqual(e.subject, "Test Subject")
            self.assertIn("alice@example.com", e.sender)
            self.assertIn("Hello world", e.text)
            self.assertEqual(e.attachment_header, [])
            self.assertEqual(e.urls, [])

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_extracts_urls_from_html(self, _mock_lemma):
        eml = (
            "From: X <x@example.com>\r\n"
            "Subject: H\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n"
            "<html><body>"
            "<a href='https://example.com/a'>A</a>"
            "<a href=\"/b\">B</a>"
            "</body></html>\r\n"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as td:
            eml_path = os.path.join(td, "msg.eml")
            with open(eml_path, "wb") as f:
                f.write(eml)

            e = m.Email(email_path=eml_path, attachment_output_path=os.path.join(td, "att"))
            self.assertIn("https://example.com/a", e.urls)
            self.assertIn("/b", e.urls)
            self.assertTrue(len(e.text) > 0)  # html stripped -> text

