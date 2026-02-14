import unittest
from unittest.mock import patch, MagicMock
import time
from datetime import datetime, timezone

from DocChecking.DocCheck import DocCheck, risk_score_calculate


# ---------- Base helper to create checker without init ----------
class BaseDocChecker(unittest.TestCase):

    def make_checker(self, files=None, internet=True, metadata=None, extensions=None):
        d = DocCheck.__new__(DocCheck)
        d.files = files or []
        d.connectivity = internet
        d.file_score = {f: 0 for f in d.files}
        d.triggered_checks = {f: [] for f in d.files}
        d.document_path = "Resources/TEMP_FILES"
        d.metadata_date = metadata or {f: {"creation": 0, "modified": 0} for f in d.files}
        d.extensions = extensions or {f: f.split('.')[-1] for f in d.files}
        return d


# ---------- Initialization tests ----------
class TestDocCheckInit(unittest.TestCase):

    @patch.object(DocCheck, "_DocCheck__internet_check", return_value=False)
    @patch.object(DocCheck, "_DocCheck__get_files", return_value=[])
    def test_init_no_files(self, *_):
        checker = DocCheck(email_path=None)
        self.assertEqual(checker.files, [])
        self.assertEqual(checker.file_score, {})
        self.assertFalse(checker.connectivity)
        self.assertEqual(checker.triggered_checks, {})


# ---------- Extension extraction ----------
class TestExtensionExtraction(BaseDocChecker):

    def test_multiple_extensions_penalty(self):
        d = self.make_checker(files=["safe.pdf", "evil.exe.pdf"])
        d._DocCheck__extension_extraction()
        self.assertEqual(d.extensions["safe.pdf"], "pdf")
        self.assertEqual(d.extensions["evil.exe.pdf"], "pdf")
        self.assertEqual(d.file_score["evil.exe.pdf"], 20)
        self.assertIn("multiple_extensions", d.triggered_checks["evil.exe.pdf"])


# ---------- Metadata checks ----------
class TestMetadataChecks(BaseDocChecker):

    def test_creation_equals_modified(self):
        ts = int(time.time())
        d = self.make_checker(
            files=["file.doc"],
            metadata={"file.doc": {"creation": ts, "modified": ts}}
        )
        d.metadata_check()
        self.assertIn("metadata_date_anomaly", d.triggered_checks["file.doc"])
        self.assertEqual(d.file_score["file.doc"], 30)

    def test_future_dates(self):
        ts = int(time.time())
        d = self.make_checker(
            files=["future.doc"],
            metadata={"future.doc": {"creation": ts + 1000, "modified": ts + 500}}
        )
        d.metadata_check()
        self.assertIn("metadata_date_anomaly", d.triggered_checks["future.doc"])

    def test_missing_dates_no_crash(self):
        d = self.make_checker(files=["no_dates.doc"], metadata={"no_dates.doc": {}})
        d.metadata_check()
        self.assertEqual(d.file_score["no_dates.doc"], 0)
        self.assertEqual(d.triggered_checks["no_dates.doc"], [])


# ---------- Macro detection ----------
class TestMacroDetection(BaseDocChecker):

    @patch.object(DocCheck, "extract_wordlist", return_value=["docm"])
    def test_macro_with_vba(self, _):
        d = self.make_checker(files=["file.docm"], extensions={"file.docm": "docm"})
        with patch.object(DocCheck, "macro_check", return_value=True):
            d.macro_check_all()
        self.assertIn("macro_detected", d.triggered_checks["file.docm"])
        self.assertEqual(d.file_score["file.docm"], 110)

    @patch.object(DocCheck, "extract_wordlist", return_value=["docm"])
    def test_macro_without_vba(self, _):
        d = self.make_checker(files=["file.docm"], extensions={"file.docm": "docm"})
        with patch.object(DocCheck, "macro_check", return_value=False):
            d.macro_check_all()
        self.assertIn("macro_detected", d.triggered_checks["file.docm"])
        self.assertEqual(d.file_score["file.docm"], 10)


# ---------- Archive checks ----------
class TestArchiveChecks(BaseDocChecker):

    @patch.object(DocCheck, "extract_wordlist", return_value=["zip", "rar"])
    def test_encrypted_zip_and_high_risk_nested(self, _):
        d = self.make_checker(files=["payload.zip"], extensions={"payload.zip": "zip"})
        # Simulate archive with encrypted flag and high-risk nested file
        archive_content = {"encrypted": True, "filenames": ["evil.exe", "doc.docx"]}
        with patch.object(DocCheck, "archive_content_check", return_value=archive_content):
            with patch.object(DocCheck, "extract_wordlist", return_value=["exe"]):
                d.archive_check()
        self.assertIn("encrypted_archive", d.triggered_checks["payload.zip"])
        self.assertIn("high_risk_extension", d.triggered_checks["payload.zip"])

    @patch.object(DocCheck, "archive_content_check", return_value=None)
    def test_empty_archive(self, _):
        d = self.make_checker(files=["empty.zip"], extensions={"empty.zip": "zip"})
        d.archive_check()
        self.assertNotIn("encrypted_archive", d.triggered_checks["empty.zip"])


# ---------- High-risk extension ----------
class TestHighRiskExtension(BaseDocChecker):

    @patch.object(DocCheck, "extract_wordlist", return_value=["exe", "scr"])
    def test_high_risk_flag_sets_instant(self, _):
        d = self.make_checker(files=["evil.exe"], extensions={"evil.exe": "exe"})
        d.high_risk_extension_check()
        self.assertIn("high_risk_extension", d.triggered_checks["evil.exe"])
        # Score is treated as instant 100% in risk_score_calculate
        final, _, _ = risk_score_calculate(100, d.file_score, True, d.triggered_checks)
        self.assertEqual(final["evil.exe"], 100.0)


# ---------- VirusTotal ----------
class TestVirusTotal(unittest.TestCase):

    @patch("DocChecking.DocCheck.VirusTotalAPIFiles")
    @patch("DocChecking.DocCheck.VirusTotalAPIAnalyses")
    @patch("builtins.open", new_callable=MagicMock)  # Prevent actual file read
    def test_malicious_detected(self, mock_open, mock_analysis, mock_files):
        mock_files.return_value.upload.return_value = '{"data":{"id":"123"}}'
        mock_analysis.return_value.get_report.return_value = (
            '{"data":{"attributes":{"stats":{"malicious":10,"harmless":0,"suspicious":0}}}}'
        )

        d = DocCheck(email_path=None)
        d.connectivity = True
        d.document_path = "/fake/path"
        d.files = ["evil.docx"]
        d.file_score = {"evil.docx": 0}
        d.triggered_checks = {"evil.docx": []}

        d.virus_total()

        # Should now trigger instant 100% risk
        self.assertIn("virus_total", d.triggered_checks["evil.docx"])
        final, _, _ = risk_score_calculate(100, d.file_score, True, d.triggered_checks)
        self.assertEqual(final["evil.docx"], 100.0)

    @patch("DocChecking.DocCheck.VirusTotalAPIFiles")
    @patch("DocChecking.DocCheck.VirusTotalAPIAnalyses")
    @patch("builtins.open", new_callable=MagicMock)
    def test_suspicious_detected(self, mock_open, mock_analysis, mock_files):
        mock_files.return_value.upload.return_value = '{"data":{"id":"123"}}'
        mock_analysis.return_value.get_report.return_value = (
            '{"data":{"attributes":{"stats":{"malicious":0,"harmless":0,"suspicious":5}}}}'
        )

        d = DocCheck(email_path=None)
        d.connectivity = True
        d.document_path = "/fake/path"
        d.files = ["suspicious.docx"]
        d.file_score = {"suspicious.docx": 0}
        d.triggered_checks = {"suspicious.docx": []}

        d.virus_total()

        self.assertIn("virus_total", d.triggered_checks["suspicious.docx"])
        final, _, _ = risk_score_calculate(100, d.file_score, True, d.triggered_checks)
        self.assertEqual(final["suspicious.docx"], 100.0)

    @patch("DocChecking.DocCheck.VirusTotalAPIFiles")
    @patch("DocChecking.DocCheck.VirusTotalAPIAnalyses")
    def test_harmless_file(self, mock_analysis, mock_files):
        mock_files.return_value.upload.return_value = '{"data":{"id":"123"}}'
        mock_analysis.return_value.get_report.return_value = (
            '{"data":{"attributes":{"stats":{"malicious":0,"harmless":10,"suspicious":0}}}}'
        )

        d = DocCheck(email_path=None)
        d.connectivity = True
        d.files = ["safe.docx"]
        d.file_score = {"safe.docx": 0}
        d.triggered_checks = {"safe.docx": []}

        d.virus_total()

        # Harmless file should not trigger
        self.assertNotIn("virus_total", d.triggered_checks["safe.docx"])
        final, _, _ = risk_score_calculate(100, d.file_score, True, d.triggered_checks)
        self.assertEqual(final["safe.docx"], 0.0)

    def test_no_internet(self):
        d = DocCheck(email_path=None)
        d.connectivity = False
        d.files = ["offline.docx"]
        d.file_score = {"offline.docx": 0}
        d.triggered_checks = {"offline.docx": []}

        result = d.virus_total()
        self.assertFalse(result)
        final, _, _ = risk_score_calculate(100, d.file_score, False, d.triggered_checks)
        self.assertEqual(final["offline.docx"], 0.0)


# ---------- Full run_all_checks ----------
class TestFullRunAllChecks(BaseDocChecker):

    @patch.object(DocCheck, "extract_wordlist", side_effect=[["exe"], ["docm"], ["zip"], ["exe"]])
    @patch.object(DocCheck, "macro_check", return_value=True)
    @patch.object(DocCheck, "archive_content_check", return_value={"encrypted": True, "filenames": ["evil.exe"]})
    def test_run_all_checks_combined(self, *_):
        d = self.make_checker(files=["evil.exe", "macro.docm", "archive.zip"],
                              extensions={"evil.exe": "exe", "macro.docm": "docm", "archive.zip": "zip"})
        max_score, file_score, conn, triggered = d.run_all_checks()
        self.assertEqual(set(file_score.keys()), {"evil.exe", "macro.docm", "archive.zip"})
        self.assertIn("high_risk_extension", triggered["evil.exe"])
        self.assertIn("macro_detected", triggered["macro.docm"])
        self.assertIn("encrypted_archive", triggered["archive.zip"])
        self.assertTrue(all(score >= 0 for score in file_score.values()))


# ---------- Risk score calculation ----------
class TestRiskScoreCalculationEdgeCases(unittest.TestCase):

    def test_instant_flag_capped_at_100(self):
        triggered = {"evil.exe": ["high_risk_extension"]}
        file_score = {"evil.exe": 999999}
        final, _, _ = risk_score_calculate(100, file_score, True, triggered)
        self.assertEqual(final["evil.exe"], 100.0)

    def test_regular_percentage_calculation(self):
        triggered = {"file.exe": []}
        file_score = {"file.exe": 50}
        final, _, _ = risk_score_calculate(200, file_score, True, triggered)
        self.assertEqual(final["file.exe"], 25.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
