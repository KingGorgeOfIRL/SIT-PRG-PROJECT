from email import policy
from email.parser import BytesParser
from email.message import Message
from html.parser import HTMLParser
from io import StringIO
import os
from typing import Dict, List, Union, Optional,Tuple,Any
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

def init_file(
    path: str,
    conv_to_list: bool = False,
    inverse: bool = False,
    encoding: Optional[str] = "utf-8"
    ) -> Union[Dict[str, Union[str, float]], List[List[str]]]:
    
    #Load a keyword file and convert it into a structured data format.

    output_dict: Dict[str, Union[str, float]] = {}
    output_list: List[List[str]] = []

    if not path:
        return output_list if conv_to_list else output_dict

    with open(path, "r", encoding=encoding) as file:
        for raw_line in file:
            line = raw_line.strip()

            # Skip empty or comment lines
            if not line or line.startswith("#"):
                continue
            # Split line into fields
            parts = [p.strip() for p in (line.split(",") if "," in line else line.split())]
            if conv_to_list:
                output_list.append(parts)
                continue

            # Dictionary mode requires exactly two fields
            if len(parts) != 2:
                continue  # malformed line; ignore safely
            key, value = parts
            
            # Attempt numeric conversion
            try:
                value = int(value)
            except ValueError:
                try:
                    value = float(value)
                except ValueError:
                    pass  # keep as string
            if inverse:
                output_dict[str(value)] = key
            else:
                output_dict[key] = value

    return output_list if conv_to_list else output_dict

class Email:
    #Email object represents each email instance
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
    
    #convert a single raw email file into a .eml file.
    def convert_to_eml(input_path: str, output_path: str = None) -> str:

        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")

        # If no output path provided, replace extension with .eml
        if output_path is None:
            base_name = os.path.splitext(input_path)[0]
            output_path = base_name + ".eml"

        with open(input_path, "rb") as src:
            raw_data = src.read()

        with open(output_path, "wb") as dst:
            dst.write(raw_data)

        return output_path
    
    
    def __repr__(self):
        return f"Email<Subject:{self.subject},Sender:{self.sender}>"
