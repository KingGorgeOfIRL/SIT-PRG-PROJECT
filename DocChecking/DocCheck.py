import os
from typing import Dict, List, Union, Optional,Tuple,Any
from email import policy
from email import policy
from email.parser import BytesParser
from email.message import Message
from html.parser import HTMLParser
from io import StringIO
import base64
import re

class _MLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.reset()
        self.strict = False
        self.convert_charrefs= True
        self.text = StringIO()

    def handle_data(self, d):
        self.text.write(d)

    def get_data(self):
        return self.text.getvalue()

def _strip_tags(html):
    s = _MLStripper()
    s.feed(html)
    return s.get_data()

def _decode_part_bytes(part: Message, default_charset: str = "utf-8") -> str:
    """
    Decode a text/* MIME part to a Unicode string using declared charset
    (fallback to utf-8 with errors ignored).
    """
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""

    charset = part.get_content_charset() or default_charset
    try:
        return payload.decode(charset, errors="ignore")
    except LookupError:
        # Unknown charset -> fallback
        return payload.decode(default_charset, errors="ignore")

def _extract_hrefs_from_html(html: str) -> List[str]:
    #Extract href targets from HTML using a regex (lightweight, not a full HTML parser).
    # Handles href="..." and href='...'
    return re.findall(r"""href\s*=\s*['"]([^'"]+)['"]""", html, flags=re.IGNORECASE)

def _safe_filename(name: str, default: str = "attachment.bin") -> str:
    #Prevent directory traversal and strip unsafe characters.
    if not name:
        return default
    name = os.path.basename(name)
    # Replace anything sketchy with underscore
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or default

class Email:
    def __init__(
        self,
        email_path: str,
        attachment_output_path: str = "Resources/TEMP_FILES",
    ):
        self.email_path: str = email_path
        self.attachment_output_path: str = attachment_output_path
        self.raw = None
        self.headers = None
        self.subject = None
        self.sender = None
        self.text = None
        self.attachment_header = None
        self.urls = None
        if self.email_path:
            # Parse full message
            self.raw: Message = self.__parse_eml()

            # Extract headers dict safely
            self.headers: Dict[str, str] = self.__extract_headers(self.raw)

            self.subject: str = self.headers.get("Subject", "") or ""
            self.sender: str = self.headers.get("From", "") or ""

            # Extract body + attachments + urls
            self.text, self.attachment_header, self.urls = self.__extract_body(self.raw)
   
    def __parse_eml(self) -> Message:
        #Parse the EML file in binary mode using BytesParser.
        with open(self.email_path, "rb") as f:
            return BytesParser(policy=policy.default).parse(f)

    def __extract_headers(self, msg: Message) -> Dict[str, str]:
        #Convert message headers into a plain dict.
        out: Dict[str, str] = {}
        for k, v in msg.items():
            out[k] = str(v)
        return out
    
    def __save_attachment(self, part: Message) -> Optional[Dict[str, Any]]:
        """
        Save an attachment part to disk and return metadata.
        Uses decoded bytes rather than manually handling base64 strings.
        """
        os.makedirs(self.attachment_output_path, exist_ok=True)

        raw_bytes = part.get_payload(decode=True)
        if raw_bytes is None:
            return None

        filename = _safe_filename(part.get_filename() or "attachment.bin")
        out_path = os.path.join(self.attachment_output_path, filename)

        # Write bytes to file
        with open(out_path, "wb") as f:
            f.write(raw_bytes)

        # Minimal metadata
        meta: Dict[str, Any] = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "content_disposition": part.get_content_disposition(),
            "size_bytes": len(raw_bytes),
            "saved_to": out_path,
        }

        # Include any useful Content-Disposition params (e.g., name=)
        try:
            params = part.get_params(header="content-disposition", failobj=[])
            if params:
                meta["content_disposition_params"] = dict(params)
        except Exception:
            pass

        return meta
    
    def __extract_body(self, msg: Message) -> Tuple[str, List[Dict[str, Any]], List[str]]:
        """
        Extract best-effort plain text body, save attachments, and collect URLs.
        Prefers text/plain; falls back to text/html if needed.
        """
        attachments: List[Dict[str, Any]] = []
        urls: List[str] = []

        plain_parts: List[str] = []
        html_parts: List[str] = []

        # Walk over MIME structure
        for part in msg.walk():
            if part.is_multipart():
                continue

            ctype = part.get_content_type()
            cdisp = part.get_content_disposition()  # "attachment", "inline", or None

            # Attachments: anything explicitly marked attachment OR has filename
            filename = part.get_filename()
            if cdisp == "attachment" or filename:
                meta = self.__save_attachment(part)
                if meta:
                    attachments.append(meta)
                continue

            # Body text extraction
            if ctype == "text/plain":
                plain_parts.append(_decode_part_bytes(part))
            elif ctype == "text/html":
                html = _decode_part_bytes(part)
                html_parts.append(html)
                urls.extend(_extract_hrefs_from_html(html))

        # Prefer plaintext if available, otherwise use HTML->text
        if plain_parts:
            body_text = "\n".join(p for p in plain_parts if p).strip()
        else:
            combined_html = "\n".join(h for h in html_parts if h).strip()
            body_text = _strip_tags(combined_html) if combined_html else ""

        return body_text, attachments, urls
    
    def __repr__(self):
        return f"Email<Subject:{self.subject},Sender:{self.sender}>"

















from socket import create_connection
from zipfile import ZipFile
from json import loads
from struct import unpack
from time import time
from datetime import datetime, timezone
from os import listdir, remove, path
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIAnalyses
from email.utils import parsedate_to_datetime
#from LangAnalysis import Email

class DocCheck(Email):

    RISK_WEIGHTS = {
        "metadata_date_anomaly": 30,
        "macro_detected": 100,
        "archive_extension": 10,
        "encrypted_archive": 10,
    }

    RISK_WEIGHTS_ONLINE = {
        "virus_total": 50
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

        if check_name in self.RISK_WEIGHTS or check_name in self.RISK_WEIGHTS_ONLINE:
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

    # virus total online
    def virus_total(self):
        if not self.connectivity:
            return False
        API_KEY = '0f91624513c562fc371b980638f0bf815e54fa4e52e8fb763c29113d0d02947a'
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
                    self.__apply_risk_score("virus_total", file_name, 50)
            except:
                continue
        return True

    def run_all_checks(self):

        max_score = sum(self.RISK_WEIGHTS.values())

        self.high_risk_extension_check()
        self.metadata_check()
        self.macro_check_all()
        self.archive_check()

        if self.connectivity:
            self.virus_total()
            max_score = sum(self.RISK_WEIGHTS.values()) + sum(self.RISK_WEIGHTS_ONLINE.values())

        return max_score, self.file_score, self.connectivity, self.triggered_checks

# unified risk score calculator
def risk_score_calculate(max_score: int, file_risk_scores: dict, connectivity: bool, triggered_checks: dict):
    final_file_score = {}

    for file_name, score in file_risk_scores.items():

        if "high_risk_extension" in triggered_checks.get(file_name, []):
            final_file_score[file_name] = 100.0
            continue

        final_file_score[file_name] = round(
            min(score / max_score * 100, 100), 2
        )

    ranked_files = sorted(final_file_score.items(), key=lambda x: x[1], reverse=True)

    print(final_file_score, triggered_checks)
    return final_file_score, triggered_checks, ranked_files


checker = DocCheck("Resources/DATASET/DocCheck3.eml")
max_score, file_score, internet_connection, triggered_checks = checker.run_all_checks()
risk_score_calculate(max_score, file_score, internet_connection, triggered_checks)