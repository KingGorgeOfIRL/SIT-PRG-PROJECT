import unittest
from unittest.mock import patch
import os
import tempfile

class TestDetectProb(unittest.TestCase):
    def test_empty_tokens(self):
        prob, freq = m.detect_prob([], {"bank": 10.0}, None)
        self.assertEqual(prob, 0.0)
        self.assertEqual(freq, {})

    def test_empty_keywords(self):
        prob, freq = m.detect_prob(["bank"], {}, None)
        self.assertEqual(prob, 0.0)
        self.assertEqual(freq, {})

    def test_frequency_none_initializes(self):
        prob, freq = m.detect_prob(["bank"], {"bank": 10.0}, None)
        self.assertEqual(prob, 10.0)
        self.assertEqual(freq, {"bank": 1})

    def test_single_keyword_match(self):
        prob, freq = m.detect_prob(["bank"], {"bank": 10.0}, {})
        self.assertEqual(prob, 10.0)
        self.assertEqual(freq["bank"], 1)

    def test_multiple_occurrences(self):
        prob, freq = m.detect_prob(["bank", "bank", "x"], {"bank": 10.0}, {})
        self.assertEqual(prob, 20.0)
        self.assertEqual(freq["bank"], 2)

    def test_multiple_keywords(self):
        prob, freq = m.detect_prob(["bank", "account"], {"bank": 10.0, "account": 20.0}, {})
        self.assertEqual(prob, 30.0)
        self.assertEqual(freq["bank"], 1)
        self.assertEqual(freq["account"], 1)

    def test_longest_match_first(self):
        keywords = {"process payment": 30.0, "process payment urgently": 60.0}
        prob, freq = m.detect_prob(["process", "payment", "urgently"], keywords, {})
        self.assertEqual(prob, 60.0)
        self.assertEqual(freq, {"process payment urgently": 1})

    def test_overlapping_no_double_count(self):
        prob, freq = m.detect_prob(["a", "b"], {"a b": 50.0, "b": 10.0}, {})
        self.assertEqual(prob, 50.0)
        self.assertEqual(freq, {"a b": 1})

    def test_frequency_accumulates(self):
        prob1, freq = m.detect_prob(["bank"], {"bank": 10.0}, {})
        prob2, freq = m.detect_prob(["bank", "bank"], {"bank": 10.0}, freq)
        self.assertEqual(prob1, 10.0)
        self.assertEqual(prob2, 20.0)
        self.assertEqual(freq["bank"], 3)

class TestCalcConfidence(unittest.TestCase):
    def test_observed_empty(self):
        self.assertEqual(m.calc_confidence({}, {"bank": 50.0}), 0.0)

    def test_model_empty(self):
        self.assertEqual(m.calc_confidence({"bank": 4}, {}), 0.0)

    def test_total_zero(self):
        self.assertEqual(m.calc_confidence({"bank": 0}, {"bank": 50.0}), 0.0)

    def test_single_word_count_leq_3_ignored(self):
        self.assertEqual(m.calc_confidence({"bank": 3}, {"bank": 50.0}), 0.0)

    def test_phrase_count_leq_3_not_ignored(self):
        # spaces in key => included even if <=3
        penalty = m.calc_confidence({"process payment": 2}, {"process payment": 50.0})
        self.assertAlmostEqual(penalty, 50.0, places=6)

    def test_single_word_count_gt_3_penalty(self):
        penalty = m.calc_confidence({"bank": 4}, {"bank": 50.0})
        self.assertAlmostEqual(penalty, 50.0, places=6)

    def test_multiple_terms_sum_penalty(self):
        observed = {"bank": 4, "security": 6}
        model = {"bank": 50.0, "security": 50.0}
        total = 10
        expected = abs(50.0 - (4/total)*100) + abs(50.0 - (6/total)*100)
        self.assertAlmostEqual(m.calc_confidence(observed, model), expected, places=6)

    def test_missing_model_key_expected_zero(self):
        observed = {"unknown": 4}
        model = {"bank": 1.0}  # model non-empty so function runs
        # total=4 => observed_pct=100, expected=0
        self.assertAlmostEqual(m.calc_confidence(observed, model), 100.0, places=6)

class TestEmailLanguageRisk(unittest.TestCase):
    def test_invalid_total_weightage(self):
        with self.assertRaises(ValueError):
            m.email_language_risk(title="x", body="y", matrix={"f": {"x": 1.0}}, total_weightage=0)

    def test_invalid_base_confidence_score(self):
        with self.assertRaises(ValueError):
            m.email_language_risk(title="x", body="y", matrix={"f": {"x": 1.0}}, base_confidence_score=-1)

    def test_invalid_matrix(self):
        with self.assertRaises(ValueError):
            m.email_language_risk(title="x", body="y", matrix=None)

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_title_used_when_no_email(self, _mock_lemma):
        matrix = {"flag": {"urgent request": 100.0}}
        scores = m.email_language_risk(email=None, title="Urgent request", body="", matrix=matrix)
        self.assertGreater(scores["flag"], 0.0)

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_email_used_when_provided(self, _mock_lemma):
        class DummyEmail:
            subject = "urgent request"
            text = ""

        matrix = {"flag": {"urgent request": 100.0}}
        scores = m.email_language_risk(email=DummyEmail(), title="nope", body="nope", matrix=matrix)
        self.assertGreater(scores["flag"], 0.0)

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_two_flags_weight_split(self, _mock_lemma):
        matrix = {
            "finance": {"process payment": 100.0},
            "it": {"revalidate mailbox": 100.0},
        }
        scores = m.email_language_risk(title="process payment", body="", matrix=matrix, total_weightage=40)
        self.assertGreater(scores["finance"], 0.0)
        self.assertEqual(scores["it"], 0.0)

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_probability_clamped_to_100(self, _mock_lemma):
        # Ensure flag_prob exceeds 100 then clamp
        matrix = {"flag": {"pay": 80.0, "now": 80.0}}
        scores = m.email_language_risk(title="pay", body="now", matrix=matrix, total_weightage=40)

        # When clamped and short => score should be 48.0 (same reasoning as before)
        self.assertAlmostEqual(scores["flag"], 48.0, places=2)

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_confidence_penalty_reduces_score(self, _mock_lemma):
        matrix = {"flag": {"bank": 50.0}}

        # bank repeated 4 times => penalty applied (expected=50, observed=100 => penalty 50)
        scores = m.email_language_risk(title="", body="bank bank bank bank", matrix=matrix, total_weightage=40)
        self.assertAlmostEqual(scores["flag"], 24.0, places=2)

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_length_modifier_applies_for_short(self, _mock_lemma):
        matrix = {"flag": {"pay": 100.0}}
        scores_short = m.email_language_risk(title="pay", body="", matrix=matrix, total_weightage=40)

        # Force "long enough" by patching safe_get_multipliers to very small suspect thresholds
        with patch.object(m, "safe_get_multipliers", return_value=({0: 1.4}, 1, 1, [0])):
            scores_long = m.email_language_risk(title="pay", body="", matrix=matrix, total_weightage=40)

        # short should be >= long because short likely gets 1.2 length modifier
        self.assertGreaterEqual(scores_short["flag"], scores_long["flag"])

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_safe_detect_prob_degrades_on_exception(self, _mock_lemma):
        matrix = {"flag": {"pay": 100.0}}

        with patch.object(m, "detect_prob", side_effect=Exception("boom")):
            scores = m.email_language_risk(title="pay", body="", matrix=matrix, total_weightage=40)
            self.assertEqual(scores["flag"], 0.0)

    @patch.object(m, "get_lemmatizer_wordlist", return_value={})
    def test_safe_confidence_degrades_on_exception(self, _mock_lemma):
        matrix = {"flag": {"pay": 100.0}}

        with patch.object(m, "calc_confidence", side_effect=Exception("boom")):
            scores = m.email_language_risk(title="pay", body="", matrix=matrix, total_weightage=40)
            # Should still be >0 because penalty treated as 0
            self.assertGreater(scores["flag"], 0.0)

class TestSafeFilename(unittest.TestCase):
    def test_none_or_empty_returns_default(self):
        self.assertEqual(email._safe_filename(None), "attachment.bin")
        self.assertEqual(email._safe_filename(""), "attachment.bin")

    def test_strips_path_traversal(self):
        self.assertEqual(email._safe_filename("../evil.txt"), "evil.txt")

    def test_illegal_chars_sanitized(self):
        out = email._safe_filename("a?b:c*.txt")
        self.assertTrue(out.endswith(".txt"))
        self.assertNotIn("?", out)
        self.assertNotIn(":", out)
        self.assertNotIn("*", out)

    def test_only_unsafe_chars_falls_back(self):
        self.assertEqual(email._safe_filename("***"), "attachment.bin")

class TestExtractHrefs(unittest.TestCase):
    def test_extract_hrefs_quotes_and_case(self):
        html = '<a HREF="https://a.com">A</a> <a href=\'/x\'>B</a>'
        self.assertEqual(email._extract_hrefs_from_html(html), ["https://a.com", "/x"])

    def test_extract_hrefs_none(self):
        self.assertEqual(email._extract_hrefs_from_html("<p>No links</p>"), [])

class TestStripTags(unittest.TestCase):
    def test_strip_tags_basic(self):
        self.assertEqual(email._strip_tags("<p>Hello</p>").strip(), "Hello")

    def test_strip_tags_nested(self):
        self.assertEqual(email._strip_tags("<p>Hello <b>World</b></p>").strip(), "Hello World")

    def test_strip_tags_empty(self):
        self.assertEqual(email._strip_tags(""), "")

class TestInitFile(unittest.TestCase):
    def test_init_file_empty_path(self):
        self.assertEqual(email.init_file(None), {})
        self.assertEqual(email.init_file("", conv_to_list=True), [])

    def test_init_file_parses_numbers_and_strings(self):
        content = """
        # comment
        key1, 10
        key2 2.5
        key3, foo
        malformed_line_only_key
        """
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "k.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)

            d = email.init_file(p)
            self.assertEqual(d["key1"], 10)
            self.assertEqual(d["key2"], 2.5)
            self.assertEqual(d["key3"], "foo")
            self.assertNotIn("malformed_line_only_key", d)

    def test_init_file_list_mode(self):
        content = "a,1\nb 2\n"
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "k.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)

            lst = email.init_file(p, conv_to_list=True)
            self.assertEqual(lst, [["a", "1"], ["b", "2"]])

    def test_init_file_inverse(self):
        content = "word, 7\n"
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "k.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)

            d = email.init_file(p, inverse=True)
            self.assertEqual(d["7"], "word")

class TestEmail(unittest.TestCase):
    def test_email_none_path_does_not_parse(self):
        e = email.Email(email_path=None)
        self.assertIsNone(e.raw)
        self.assertIsNone(e.headers)
        self.assertIsNone(e.subject)
        self.assertIsNone(e.sender)
        self.assertIsNone(e.text)
        self.assertIsNone(e.attachment_header)
        self.assertIsNone(e.urls)

    def test_email_plain_text_parse(self):
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

            e = email.Email(email_path=eml_path, attachment_output_path=os.path.join(td, "att"))
            self.assertEqual(e.subject, "Test Subject")
            self.assertIn("alice@example.com", e.sender)
            self.assertIn("Hello world", e.text)
            self.assertEqual(e.attachment_header, [])
            self.assertEqual(e.urls, [])

    def test_email_html_extracts_urls(self):
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

            e = email.Email(email_path=eml_path, attachment_output_path=os.path.join(td, "att"))
            self.assertIn("https://example.com/a", e.urls)
            self.assertIn("/b", e.urls)
            self.assertTrue(len(e.text.strip()) > 0)

class TestConvertToEml(unittest.TestCase):
    def test_convert_to_eml_copies_bytes(self):
        raw = b"raw email bytes"
        with tempfile.TemporaryDirectory() as td:
            in_path = os.path.join(td, "rawfile")
            with open(in_path, "wb") as f:
                f.write(raw)

            out_path = email.Email.convert_to_eml(in_path)
            self.assertTrue(os.path.exists(out_path))
            self.assertTrue(out_path.endswith(".eml"))
            with open(out_path, "rb") as f:
                self.assertEqual(f.read(), raw)

    def test_convert_to_eml_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            email.Email.convert_to_eml("does_not_exist.raw")

if __name__ == "__main__":
    import main as m
    import email_extract as email
    unittest.main(verbosity=2)
