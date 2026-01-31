import os
import tempfile
import unittest
from unittest.mock import patch

# Replace with your module filename (without .py)
import LangAnalysis.main as m


class TestHtmlAndFilenameUtils(unittest.TestCase):
    def test_strip_tags(self):
        self.assertEqual(m._strip_tags("<p>Hello <b>World</b></p>").strip(), "Hello World")

    def test_extract_hrefs_from_html(self):
        html = '<a href="https://a.com">A</a> <a href=\'/path\'>B</a>'
        self.assertEqual(m._extract_hrefs_from_html(html), ["https://a.com", "/path"])

    def test_safe_filename(self):
        self.assertEqual(m._safe_filename("../evil.txt"), "evil.txt")
        self.assertEqual(m._safe_filename("subdir/..//x?.pdf"), "x_.pdf")
        self.assertEqual(m._safe_filename(""), "attachment.bin")
        self.assertEqual(m._safe_filename(None), "attachment.bin")


class TestInitFile(unittest.TestCase):
    def test_init_file_dict_mode_numbers_and_strings(self):
        content = """
        # comment
        key1, 10
        key2 2.5
        key3, not_a_number
        malformed_line_only_key
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
            self.assertEqual(d["7"], "word")


class TestTokenise(unittest.TestCase):
    @patch.object(m, "_get_lemmatizer_wordlist", return_value={"running": "run"})
    def test_tokenise_returns_list_of_lists(self, _mock_lemma):
        out = m.tokenise("Running!!!\nHello, WORLD")
        # Must be list of lines, each a list of tokens
        self.assertIsInstance(out, list)
        self.assertTrue(all(isinstance(line, list) for line in out))
        self.assertTrue(all(isinstance(tok, str) for line in out for tok in line))

        # Content checks
        # line 1: running -> run
        self.assertIn("run", out[0])
        # line 2: hello world
        self.assertIn("hello", out[1])
        self.assertIn("world", out[1])

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_tokenise_filters_non_alnum_and_lowercases(self, _mock_lemma):
        out = m.tokenise("Hi!!! $$$ 123\nMiXeD CaSe")
        self.assertEqual(out[0], ["hi", "123"])
        self.assertEqual(out[1], ["mixed", "case"])

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_tokenise_empty_lines_removed(self, _mock_lemma):
        out = m.tokenise("\n\n   \nHello\n\n")
        self.assertEqual(out, [["hello"]])


class TestDetectProb(unittest.TestCase):
    def test_detect_prob_longest_match_first(self):
        keywords = {
            "please": 5.0,
            "process payment": 30.0,
            "process payment urgently": 60.0,
        }
        tokens = ["please", "process", "payment", "urgently", "now"]

        prob, freq = m.detect_prob(tokens, keywords, {})
        # should match the longest phrase
        self.assertEqual(prob, 5.0 + 60.0)
        self.assertEqual(freq["please"], 1)
        self.assertEqual(freq["process payment urgently"], 1)
        self.assertNotIn("process payment", freq)

    def test_detect_prob_multiple_occurrences(self):
        keywords = {"bank": 10.0}
        tokens = ["bank", "bank", "x"]
        prob, freq = m.detect_prob(tokens, keywords, {})
        self.assertEqual(prob, 20.0)
        self.assertEqual(freq["bank"], 2)

    def test_detect_prob_no_match(self):
        keywords = {"bank": 10.0}
        tokens = ["hello", "there"]
        prob, freq = m.detect_prob(tokens, keywords, {})
        self.assertEqual(prob, 0.0)
        self.assertEqual(freq, {})


class TestConfidence(unittest.TestCase):
    def test_calc_confidence_empty(self):
        self.assertEqual(m.calc_confidence({}, {"x": 1.0}), 0.0)

    def test_calc_confidence_ignores_counts_leq_3(self):
        observed = {"bank": 3, "security": 3}
        model = {"bank": 50.0, "security": 50.0}
        self.assertEqual(m.calc_confidence(observed, model), 0.0)

    def test_calc_confidence_penalty_computed(self):
        observed = {"security": 10, "bank": 4}  # both > 3 contribute
        model = {"security": 50.0, "bank": 50.0}

        total = 14
        obs_sec = (10 / total) * 100
        obs_bank = (4 / total) * 100
        expected = abs(50.0 - obs_sec) + abs(50.0 - obs_bank)

        self.assertAlmostEqual(m.calc_confidence(observed, model), expected, places=6)


class TestEmailLanguageRisk(unittest.TestCase):
    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_language_risk_requires_matrix(self, _mock_lemma):
        with self.assertRaises(ValueError):
            m.email_language_risk(body="x", title="y", matrix=None)

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_language_risk_title_used_when_no_email(self, _mock_lemma):
        matrix = {"flag": {"urgent request": 100.0}}

        # 'urgent request' is in title => should score > 0
        scores = m.email_language_risk(email=None, body="", title="Urgent request", matrix=matrix)
        self.assertGreater(scores["flag"], 0.0)

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_language_risk_weighting_and_cap(self, _mock_lemma):
        # Make prob > 100 to verify cap at 100
        matrix = {"flag": {"pay": 80.0, "now": 80.0}}

        scores = m.email_language_risk(
            email=None,
            title="pay",
            body="now",
            matrix=matrix,
            total_weightage=40,
            base_confidence_score=100,
        )

        # Only one flag => flag_weight == 40
        # prob contribution from title line (idx=0 weight 1.4): 80*1.4 = 112
        # body line (idx=1 weight 1.3): 80*1.3 = 104
        # total = 216 -> capped to 100
        # confidence_penalty uses counts; both are <=3, so penalty=0 => confidence 100
        # length_modifier = 1.2 (tokens < 300)
        # score = 40 * (100/100) * (100/100) * 1.2 = 48.0
        self.assertAlmostEqual(scores["flag"], 48.0, places=2)

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_language_risk_multiple_flags(self, _mock_lemma):
        matrix = {
            "finance": {"process payment": 100.0},
            "it": {"revalidate mailbox": 100.0},
        }

        scores = m.email_language_risk(
            email=None,
            title="Please process payment",
            body="Hello",
            matrix=matrix,
            total_weightage=40,
            base_confidence_score=100,
        )

        # total_weightage 40 / 2 flags = 20 per flag
        self.assertGreater(scores["finance"], 0.0)
        self.assertEqual(scores["it"], 0.0)


class TestEmailParsing(unittest.TestCase):
    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_parses_plain_text(self, _mock_lemma):
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
            self.assertTrue(len(e.text.strip()) > 0)

    @patch.object(m, "_get_lemmatizer_wordlist", return_value={})
    def test_email_saves_attachment(self, _mock_lemma):
        # Multipart with one plain part and one attachment
        eml = (
            "From: A <a@x.com>\r\n"
            "Subject: With Attachment\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=BOUND\r\n"
            "\r\n"
            "--BOUND\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Body text\r\n"
            "--BOUND\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"test.bin\"\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "aGVsbG8=\r\n"  # "hello"
            "--BOUND--\r\n"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as td:
            eml_path = os.path.join(td, "msg.eml")
            att_dir = os.path.join(td, "att")
            with open(eml_path, "wb") as f:
                f.write(eml)

            e = m.Email(email_path=eml_path, attachment_output_path=att_dir)

            self.assertEqual(len(e.attachment_header), 1)
            meta = e.attachment_header[0]
            self.assertEqual(meta["filename"], "test.bin")
            self.assertTrue(os.path.exists(meta["saved_to"]))
            self.assertEqual(meta["size_bytes"], 5)  # "hello" is 5 bytes

            with open(meta["saved_to"], "rb") as f:
                self.assertEqual(f.read(), b"hello")


if __name__ == "__main__":
    unittest.main(verbosity=2)
