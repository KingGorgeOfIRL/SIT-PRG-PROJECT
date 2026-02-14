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
    """
    DocCheck extends the Email analysis class and focuses on
    evaluating document attachments for potential malware risks.

    The class assigns risk scores to each attachment based on
    multiple static and behavioral indicators.
    """

    # base weights used to calculate the maximum possible risk score
    RISK_WEIGHTS = {
        "metadata_date_anomaly": 30,     # suspicious timestamps
        "macro_detected": 100,            # macro presence is high risk
        "archive_extension": 10,          # archives can hide payloads
        "encrypted_archive": 10,          # encryption blocks inspection
    }

    def __init__(self, email_path=None):
        super().__init__(email_path)

        # directory where extracted attachments are stored
        self.document_path = 'Resources/TEMP_FILES'

        # check if internet is available (used for VirusTotal)
        self.connectivity:[bool] = self.__internet_check()

        # collect attachment filenames
        self.files:[str] = self.__get_files()

        # extract and store file extensions
        self.extensions:{str: str} = self.__extension_extraction()

        # extract creation/modification metadata from email headers
        self.metadata_date:{str: {str: int}} = self.__date_extraction()

        # initialize risk score per file
        self.file_score:{str: int} = {file_name: 0 for file_name in self.files} or None

        # track which checks triggered per file (for explainability)
        self.triggered_checks:{str: [str]} = {file_name: [] for file_name in self.files}
    # internet check
    def __internet_check(self):
        """
        Attempts a lightweight socket connection to determine
        whether external services (VirusTotal) can be used.
        """
        try:
            s = create_connection(("www.google.com", 80), timeout=3)
            s.close()
            return True
        except:
            return False

    # get files in TEMP_FILES
    def __get_files(self):
        """
        Lists extracted attachment files.
        Ensures the directory exists and ignores subdirectories.
        """
        if not path.exists(self.document_path):
            return []
        return [
            name for name in listdir(self.document_path)
            if path.isfile(path.join(self.document_path, name))
        ]

    # extract extensions
    def __extension_extraction(self):
        """
        Extracts file extensions and checks for double extensions
        (e.g. invoice.pdf.exe)
        """
        extensions = {}
        for file_name in self.files:
            split_name = file_name.split('.')

            # multiple extensions increase risk score
            if len(split_name) > 2:
                self.file_score[file_name] += 20
                self.triggered_checks[file_name].append("multiple_extensions")

            extensions[file_name] = split_name[-1]
        return extensions

    # extract metadata dates
    def __date_extraction(self):
        """
        Extracts creation and modification timestamps from
        email attachment headers and converts them to epoch time.
        """
        dates = {file_name: {} for file_name in self.files}

        # if no attachment metadata exists, return empty values
        if not getattr(self, "attachment_header", None):
            return dates

        for entry in self.attachment_header:
            filename = entry['filename']

            # convert RFC822 date strings to epoch timestamps
            creation = self.to_epoch_time(entry.get('creation-date=', ''))
            modified = self.to_epoch_time(entry.get('modification-date=', ''))

            dates[filename] = {"creation": creation, "modified": modified}
        return dates

    # dynamically apply risk score
    def __apply_risk_score(self, check_name, file_name, score):
        """
        Adds a risk score to a file and records which check caused it.
        Prevents duplicate trigger entries.
        """
        if check_name in self.RISK_WEIGHTS:
            self.file_score[file_name] += score

        if check_name not in self.triggered_checks[file_name]:
            self.triggered_checks[file_name].append(check_name)

    # standadize time stamp to epoch
    def to_epoch_time(self, date_str):
        """
        Converts an email date string into a UTC epoch timestamp.
        Returns 0 if parsing fails.
        """
        try:
            dt = parsedate_to_datetime(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except:
            return 0

    # extract wordlist
    def extract_wordlist(self, filename=None):
        """
        Loads wordlists used for extension-based detection
        """
        with open(f'Resources/WORDLISTS/doc_check/{filename}', "r", encoding="utf-8") as f:
            return f.read().split()

    # high risk extension check
    def high_risk_extension_check(self):
        """
        Flags files with extensions commonly associated with malware.
        These trigger an instant maximum risk score.
        """
        wordlist = self.extract_wordlist('high_risk_extensions.txt')

        for file_name in self.files:
            if self.extensions[file_name] in wordlist:
                self.__apply_risk_score(
                    "high_risk_extension",
                    file_name,
                    1000000
                )
        return True

    # metadata date anomaly
    def metadata_check(self):
        """
        Detects suspicious timestamp behavior:
        - identical creation and modification dates
        - dates set in the future
        """
        # get current time
        now = int(time())

        for file_name, dates in self.metadata_date.items():
            if not dates:
                continue

            if (dates["creation"] == dates["modified"] or dates["creation"] >= now or dates["modified"] >= now):
                self.__apply_risk_score("metadata_date_anomaly", file_name, 30)
        return True

    # macro extension + detection
    def macro_check_all(self):
        """
        Identifies macro-enabled documents and scans their contents
        for embedded VBA projects (macro)
        """
        wordlist = self.extract_wordlist('macro_extensions.txt')

        for file_name in self.files:
            if self.extensions[file_name] in wordlist:
                # macro-capable extension
                self.__apply_risk_score("macro_detected", file_name, 10)

                # confirmed VBA payload (macro present)
                if self.macro_check(file_name):
                    self.__apply_risk_score("macro_detected", file_name, 100)
        return True

    # detect VBA payload in macro-capable files
    def macro_check(self, file_name:str):
        """
        Checks inside Office documents (ZIP format) for vbaProject.bin,
        which indicates embedded macros.
        """
        try:
            with ZipFile(f"{self.document_path}/{file_name}") as z:
                return any("vbaProject.bin" in name for name in z.namelist())
        except:
            return False

    # archive checks
    def archive_check(self):
        """
        Evaluates archive files:
        - checks if archive is encrypted
        - inspects contained filenames for high-risk extensions (if ZIP)
        """
        wordlist = self.extract_wordlist('archive_extensions.txt')

        for file_name in self.files:

            # check if is archive file
            if self.extensions[file_name] in wordlist:
                self.__apply_risk_score("archive_extension", file_name, 10)
            
            # check if is zip
            if self.extensions[file_name] == 'zip':
                # check for content (filenames & extension)
                content = self.archive_content_check(file_name)

                if content:
                    # if archive is encrypted
                    if content.get("encrypted"):
                        self.__apply_risk_score("encrypted_archive", file_name, 10)

                    # inspect files inside the archive
                    archive_ext = {f: f.split('.')[-1] for f in content["filenames"] if '.' in f.split('/')[-1]}

                    for f, ext in archive_ext.items():
                        # check if file in archive contain high risk extension
                        if ext in self.extract_wordlist('high_risk_extensions.txt'):
                            self.__apply_risk_score("high_risk_extension", file_name, 1000000)
        return True

    # peek in archive files to check filenames within
    def archive_content_check(self, file_name:str):
        """
        Parses ZIP headers manually to detect encryption flags
        and extract internal filenames without full extraction.
        """
        result = {"encrypted": False, "filenames": []}

        try:
            with open(f'{self.document_path}/{file_name}', "rb") as f:
                data = f.read()

            i = 0
            while i < len(data):
                # ZIP local file header signature
                if data[i:i+4] == b'PK\x03\x04':
                    flag = unpack("<H", data[i+6:i+8])[0] # byte 6 & 7

                    # bit 0x1 = encryption
                    if flag & 0x1:
                        result["encrypted"] = True

                    # get file name length
                    fname_len = unpack("<H", data[i+26:i+28])[0] # byte 26 & 27
                    # get extra field length
                    extra_len = unpack("<H", data[i+28:i+30])[0] # byte 28 & 29

                    # filename
                    fname = data[i+30:i+30+fname_len].decode(errors="ignore") # byte 30 to 30+filename length

                    if fname:
                        result["filenames"].append(fname)

                    # move on to the next file
                    i += 30 + fname_len + extra_len
                else:
                    i += 1

            return result if result["filenames"] else None
        except:
            return None

    # virus total online [100%]
    def virus_total(self):
        """
        Uploads files to VirusTotal and checks engine verdicts.
        Malicious or suspicious results immediately max the risk score.
        """
        if not self.connectivity:
            return False

        API_KEY = 'aab69934a49f25e21cc381f20ad2be87133207bfd0bcfe41b6f2728515307c75'
        vt_files = VirusTotalAPIFiles(API_KEY)
        vt_analysis = VirusTotalAPIAnalyses(API_KEY)

        for file_name in self.files:
            try:
                # get analysis id
                result = vt_files.upload(f"{self.document_path}/{file_name}")
                analysis_id = loads(result)["data"]["id"]

                # get report (using analysis id)
                report = vt_analysis.get_report(analysis_id)
                stats = loads(report)['data']['attributes']['stats']

                # select the most dominant category. returns a dict {category: int, ...}
                highest = max(stats, key=stats.get)

                if highest in ['malicious', 'suspicious']:
                    self.__apply_risk_score("virus_total", file_name, 1000000)
            except:
                continue
        return True

    def run_all_checks(self):
        """
        Executes all document analysis checks and
        returns scoring data for final risk calculation.
        """
        max_score = sum(self.RISK_WEIGHTS.values())

        self.high_risk_extension_check()
        self.metadata_check()
        self.macro_check_all()
        self.archive_check()

        if self.connectivity == True:
            #self.virus_total()
            pass

        max_score = sum(self.RISK_WEIGHTS.values())

        return (max_score, self.file_score, self.connectivity, self.triggered_checks)


# unified risk score calculator
def risk_score_calculate(max_score: int, file_risk_scores: dict, connectivity: bool, triggered_checks: dict):
    """
    Converts raw risk scores into normalized percentages
    and prioritizes instant-flag detections.
    """
    final_file_score = {}

    for file_name, score in file_risk_scores.items():
        # 100% checks
        instant_flag_checks = ["high_risk_extension", "virus_total"]

        # instant critical detections override all scoring
        if any(check in triggered_checks.get(file_name, []) for check in instant_flag_checks):
            final_file_score[file_name] = 100.0
            continue

        # normalize score into percentage
        final_file_score[file_name] = round(min(score / max_score * 100, 100), 2)

    # rank files from highest to lowest risk
    ranked_files = sorted(final_file_score.items(), key=lambda x: x[1], reverse=True)

    return final_file_score, triggered_checks, ranked_files


# checker = DocCheck("Resources/DATASET/DocCheck3.eml")
# max_score, file_score, internet_connection, triggered_checks = checker.run_all_checks()
# risk_score_calculate(max_score, file_score, internet_connection, triggered_checks)
