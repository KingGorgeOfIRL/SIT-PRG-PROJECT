from socket import create_connection
from zipfile import ZipFile
from json import loads
from struct import unpack
from time import time
from datetime import datetime, timezone
from os import listdir, remove, path
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIAnalyses
from email.utils import parsedate_to_datetime
from LangAnalysis import Email

class DocCheck(Email):

    RISK_WEIGHTS = {
        "metadata_date_anomaly": 30,
        "macro_detected": 100,
        "archive_extension": 10,
        "encrypted_archive": 10,
    }

    def __init__(self, email_path=None):
        super().__init__(email_path)

        self.document_path = 'Resources/TEMP_FILES'
        self.connectivity = self.__internet_check()
        self.files = self.__get_files()
        self.extensions = self.__extension_extraction()
        self.metadata_date = self.__date_extraction()
        self.file_score = {file_name: 0 for file_name in self.files}
        self.triggered_checks = {file_name: [] for file_name in self.files}

    # internet check
    def __internet_check(self):
        try:
            s = create_connection(("www.google.com", 80), timeout=3)
            s.close()
            return True
        except:
            return False

    # get files in TEMP_FILES
    def __get_files(self):
        if not path.exists(self.document_path):
            return []
        return [name for name in listdir(self.document_path) if path.isfile(path.join(self.document_path, name))]

    # extract extensions
    def __extension_extraction(self):
        extensions = {}
        for file_name in self.files:
            split_name = file_name.split('.')
            if len(split_name) > 2:
                self.file_score[file_name] += 20
                self.triggered_checks[file_name].append("multiple_extensions")
            extensions[file_name] = split_name[-1]
        return extensions

    # extract metadata dates
    def __date_extraction(self):
        dates = {file_name: {} for file_name in self.files}
        if not getattr(self, "attachment_header", None):
            return dates

        for entry in self.attachment_header:
            filename = entry['filename']
            creation = self.to_epoch_time(entry.get('creation-date=', ''))
            modified = self.to_epoch_time(entry.get('modification-date=', ''))
            dates[filename] = {"creation": creation, "modified": modified}
        return dates

    # dynamically apply risk score
    def __apply_risk_score(self, check_name, file_name, score):

        if check_name in self.RISK_WEIGHTS:
            self.file_score[file_name] += score

        if check_name not in self.triggered_checks[file_name]:
            self.triggered_checks[file_name].append(check_name)

    def to_epoch_time(self, date_str):
        try:
            dt = parsedate_to_datetime(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except:
            return 0

    # extract wordlist
    def extract_wordlist(self, filename=None):
        with open(f'Resources/WORDLISTS/doc_check/{filename}', "r", encoding="utf-8") as f:
            return f.read().split()

    # high risk extension check
    def high_risk_extension_check(self):
        wordlist = self.extract_wordlist('high_risk_extensions.txt')
        for file_name in self.files:
            if self.extensions[file_name] in wordlist:
                self.__apply_risk_score("high_risk_extension", file_name, 1000000)
        return True

    # metadata date anomaly
    def metadata_check(self):
        now = int(time())
        for file_name, dates in self.metadata_date.items():
            if not dates:
                continue
            if dates["creation"] == dates["modified"] or dates["creation"] >= now or dates["modified"] >= now:
                self.__apply_risk_score("metadata_date_anomaly", file_name, 30)
        return True

    # macro extension + detection
    def macro_check_all(self):
        wordlist = self.extract_wordlist('macro_extensions.txt')
        for file_name in self.files:
            if self.extensions[file_name] in wordlist:
                self.__apply_risk_score("macro_detected", file_name, 10)
                if self.macro_check(file_name):
                    self.__apply_risk_score("macro_detected", file_name, 100)
        return True

    def macro_check(self, file_name):
        try:
            with ZipFile(f"{self.document_path}/{file_name}") as z:
                return any("vbaProject.bin" in name for name in z.namelist())
        except:
            return False

    # archive checks
    def archive_check(self):
        wordlist = self.extract_wordlist('archive_extensions.txt')
        for file_name in self.files:
            if self.extensions[file_name] in wordlist:
                self.__apply_risk_score("archive_extension", file_name, 10)
            if self.extensions[file_name] == 'zip':
                content = self.archive_content_check(file_name)
                if content:
                    if content.get("encrypted"):
                        self.__apply_risk_score("encrypted_archive", file_name, 10)
                    archive_ext = {f: f.split('.')[-1] for f in content["filenames"] if '.' in f.split('/')[-1]}
                    for f, ext in archive_ext.items():
                        if ext in self.extract_wordlist('high_risk_extensions.txt'):
                            self.__apply_risk_score("high_risk_extension", file_name, 1000000)
        return True

    def archive_content_check(self, file_name):
        result = {"encrypted": False, "filenames": []}
        try:
            with open(f'{self.document_path}/{file_name}', "rb") as f:
                data = f.read()
            i = 0
            while i < len(data):
                if data[i:i+4] == b'PK\x03\x04':
                    flag = unpack("<H", data[i+6:i+8])[0]
                    if flag & 0x1:
                        result["encrypted"] = True
                    fname_len = unpack("<H", data[i+26:i+28])[0]
                    extra_len = unpack("<H", data[i+28:i+30])[0]
                    fname = data[i+30:i+30+fname_len].decode(errors="ignore")
                    if fname:
                        result["filenames"].append(fname)
                    i += 30 + fname_len + extra_len
                else:
                    i += 1
            return result if result["filenames"] else None
        except:
            return None

    # virus total online [100%]
    def virus_total(self):
        if not self.connectivity:
            return False
        API_KEY = 'aab69934a49f25e21cc381f20ad2be87133207bfd0bcfe41b6f2728515307c75'
        vt_files = VirusTotalAPIFiles(API_KEY)
        vt_analysis = VirusTotalAPIAnalyses(API_KEY)
        for file_name in self.files:
            try:
                result = vt_files.upload(f"{self.document_path}/{file_name}")
                analysis_id = loads(result)["data"]["id"]
                report = vt_analysis.get_report(analysis_id)
                stats = loads(report)['data']['attributes']['stats']
                highest = max(stats, key=stats.get)
                if highest in ['malicious', 'suspicious']:
                    self.__apply_risk_score("virus_total", file_name, 1000000)
            except:
                continue
        return True

    def run_all_checks(self):

        max_score = sum(self.RISK_WEIGHTS.values())

        self.high_risk_extension_check()
        self.metadata_check()
        self.macro_check_all()
        self.archive_check()

        max_score = sum(self.RISK_WEIGHTS.values())

        return max_score, self.file_score, self.connectivity, self.triggered_checks

# unified risk score calculator
def risk_score_calculate(max_score: int, file_risk_scores: dict, connectivity: bool, triggered_checks: dict):
    final_file_score = {}

    for file_name, score in file_risk_scores.items():

        instant_flag_checks = ["high_risk_extension", "virus_total"]

        if any(check in triggered_checks.get(file_name, []) for check in instant_flag_checks):
            final_file_score[file_name] = 100.0
            continue

        final_file_score[file_name] = round(
            min(score / max_score * 100, 100), 2
        )

    ranked_files = sorted(final_file_score.items(), key=lambda x: x[1], reverse=True)

    #print(final_file_score, triggered_checks)
    return final_file_score, triggered_checks, ranked_files


checker = DocCheck("Resources/DATASET/DocCheck3.eml")
max_score, file_score, internet_connection, triggered_checks = checker.run_all_checks()
risk_score_calculate(max_score, file_score, internet_connection, triggered_checks)