import unittest
from unittest.mock import patch
import time

from DocChecking.DocCheck import DocCheck, risk_score_calculate


class TestDocCheckInit(unittest.TestCase):

    @patch.object(DocCheck, "_DocCheck__internet_check", return_value=False)
    @patch.object(DocCheck, "_DocCheck__get_files", return_value=[])
    def test_init_basic(self, *_):
        checker = DocCheck(email_path=None)

        self.assertEqual(checker.files, [])
        self.assertEqual(checker.file_score, {})
        self.assertFalse(checker.connectivity)
        self.assertEqual(checker.triggered_checks, {})


class TestExtensionExtraction(unittest.TestCase):

    def setUp(self):
        with patch.object(DocCheck, "_DocCheck__internet_check", return_value=False):
            self.c = DocCheck(email_path=None)
            self.c.files = ["safe.pdf", "evil.exe.pdf"]
            self.c.file_score = {f: 0 for f in self.c.files}
            self.c.triggered_checks = {f: [] for f in self.c.files}

    def test_multiple_extension_penalty(self):
        ext = self.c._DocCheck__extension_extraction()

        self.assertEqual(ext["safe.pdf"], "pdf")
        self.assertEqual(ext["evil.exe.pdf"], "pdf")
        self.assertEqual(self.c.file_score["evil.exe.pdf"], 20)
        self.assertIn("multiple_extensions", self.c.triggered_checks["evil.exe.pdf"])


class TestMetadataCheck(unittest.TestCase):

    def setUp(self):
        with patch.object(DocCheck, "_DocCheck__internet_check", return_value=False):
            self.c = DocCheck(email_path=None)
            now = int(time.time())

            self.c.metadata_date = {
                "file.doc": {
                    "creation": now,
                    "modified": now
                }
            }
            self.c.file_score = {"file.doc": 0}
            self.c.triggered_checks = {"file.doc": []}

    def test_metadata_equal_dates(self):
        self.c.metadata_check()
        self.assertEqual(self.c.file_score["file.doc"], 30)
        self.assertIn("metadata_date_anomaly", self.c.triggered_checks["file.doc"])


class TestMacroDetection(unittest.TestCase):

    @patch.object(DocCheck, "extract_wordlist", return_value=["docm"])
    @patch.object(DocCheck, "macro_check", return_value=True)
    def test_macro_file_with_macro(self, *_):
        with patch.object(DocCheck, "_DocCheck__internet_check", return_value=False):
            c = DocCheck(email_path=None)
            c.files = ["invoice.docm"]
            c.extensions = {"invoice.docm": "docm"}
            c.file_score = {"invoice.docm": 0}
            c.triggered_checks = {"invoice.docm": []}

            c.macro_check_all()

            self.assertEqual(c.file_score["invoice.docm"], 110)
            self.assertIn("macro_detected", c.triggered_checks["invoice.docm"])


class TestArchiveCheck(unittest.TestCase):

    @patch.object(DocCheck, "extract_wordlist", return_value=["zip"])
    @patch.object(DocCheck, "archive_content_check")
    def test_encrypted_zip(self, mock_archive, _):
        mock_archive.return_value = {
            "encrypted": True,
            "filenames": ["evil.exe"]
        }

        with patch.object(DocCheck, "_DocCheck__internet_check", return_value=False):
            c = DocCheck(email_path=None)
            c.files = ["payload.zip"]
            c.extensions = {"payload.zip": "zip"}
            c.file_score = {"payload.zip": 0}
            c.triggered_checks = {"payload.zip": []}

            c.archive_check()

            self.assertGreaterEqual(c.file_score["payload.zip"], 20)
            self.assertIn("encrypted_archive", c.triggered_checks["payload.zip"])


class TestVirusTotal(unittest.TestCase):

    @patch("DocChecking.DocCheck.VirusTotalAPIFiles")
    @patch("DocChecking.DocCheck.VirusTotalAPIAnalyses")
    def test_virus_total_malicious(self, mock_analysis, mock_files):
        mock_files.return_value.upload.return_value = '{"data":{"id":"123"}}'
        mock_analysis.return_value.get_report.return_value = (
            '{"data":{"attributes":{"stats":{"malicious":5,"harmless":0}}}}'
        )

        with patch.object(DocCheck, "_DocCheck__internet_check", return_value=True):
            c = DocCheck(email_path=None)
            c.files = ["evil.exe"]
            c.file_score = {"evil.exe": 0}
            c.triggered_checks = {"evil.exe": []}

            c.virus_total()

            self.assertEqual(c.file_score["evil.exe"], 50)
            self.assertIn("virus_total", c.triggered_checks["evil.exe"])


class TestRiskScoreCalculation(unittest.TestCase):

    def test_online_risk_score(self):
        max_score = 200
        scores = {"file.exe": 100}
        triggered = {"file.exe": []}

        final, _, _ = risk_score_calculate(
            max_score, scores, connectivity=True, triggered_checks=triggered
        )

        self.assertEqual(final["file.exe"], 50.0)

    def test_high_risk_caps_at_100(self):
        max_score = 200
        scores = {"evil.exe": 999999}
        triggered = {"evil.exe": ["high_risk_extension"]}

        final, _, _ = risk_score_calculate(
            max_score, scores, connectivity=False, triggered_checks=triggered
        )

        self.assertEqual(final["evil.exe"], 100.0)


if __name__ == "__main__":
    unittest.main()
