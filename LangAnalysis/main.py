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
        attachment_output_path: str = "LanguageAnalysis/Resources/TEMP_FILES",
    ):
        self.email_path: str = email_path
        self.attachment_output_path: str = attachment_output_path

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

def printable(string:str) -> bool:
    return string.isprintable()

_LEMMATIZER_WORDLIST: Optional[Dict[str, str]] = None

def _get_lemmatizer_wordlist() -> Dict[str, str]:
    #Load and cache the lemmatization wordlist once.
    global _LEMMATIZER_WORDLIST
    if _LEMMATIZER_WORDLIST is None:
        _LEMMATIZER_WORDLIST = init_file(
            path="Resources/WORDLISTS/tokenisation/lemmatization-en.txt",
            inverse=True,
            encoding="utf-8-sig"
        )
    return _LEMMATIZER_WORDLIST

def tokenise(text: str) -> List[List[str]]:
    #Strip, simplify, and tokenise text using a brute-force wordlist lemmatizer.
    tokenised: List[str] = []
    wordlist = _get_lemmatizer_wordlist()
    if not text:
        return tokenised
    
    lines = text.split("\n")
    for raw_line in lines:
        words = list(filter(printable, raw_line.split()))
        word_line = []
        for word in words:
            cleaned = re.sub(r"[^A-Za-z0-9]+", "", word).lower()
            if not cleaned:
                continue
            
            #Perform brute-force lemmatization using a lookup table
            if wordlist:
                lemma = wordlist.get(cleaned,cleaned)
            else:
                lemma = cleaned
            word_line.append(lemma)
        
        if word_line:
            tokenised.append(word_line)
    return tokenised

def increment_frequncy(frequency:dict,item):
    if item in frequency:
        frequency[item] += 1
    else:  
        frequency[item] =1
    return frequency

def init_keyword_matrix(
    keyword_folder_path:str="Resources/WORDLISTS/language_analysis"
    ) -> Dict[str, Dict[str, float]]:
    """
    Load keyword probability models from a directory of text files.
    Each file represents a risk flag category.
    """
    matrix: Dict[str, Dict[str, float]] = {}
    data = os.walk(keyword_folder_path)
    for dirpath, _, filenames in data:
        for filename in filenames:
            flag_name = filename.rsplit(".", 1)[0]
            keywords = init_file(os.path.join(dirpath, filename))
            
            flag_keywords: Dict[str, float] = {}
            
            data = keywords.items()
            for key, value in data:
                # Tokenise keyword/keyphrase and normalise to space-separated form
                tokenised_key = tokenise(key)
                normalised_key = " ".join(tokenised_key)

                # Store probability as float
                flag_keywords[normalised_key] = float(value)

            matrix[flag_name] = flag_keywords
    return matrix

def email_language_risk(
    email: Optional["Email"] = None,
    body: Optional[str] = None,
    title: Optional[str] = None,
    matrix: Optional[Dict[str, Dict[str, float]]] = None,
    total_weightage: int = 40,base_confidence_score: int = 100
) -> Dict[str, float]:
    #Calculate per-flag language risk scores for an email.

    if matrix is None:
        raise ValueError("Keyword matrix must be provided")
    if email:
        subject, body = email.subject, email.text
    else:
        subject = title
    tokens = tokenise(f"{subject}\n{body or ''}")

    weight_multiplier = {
        0: 1.4,
        1: 1.3,
        3: 1.2,
        5: 1.1,
        8: 1.0
    }

    weight_keys = sorted(weight_multiplier.keys())
    flag_weight = total_weightage / len(matrix)
    risk_scores: Dict[str, float] = {}

    for flag, keywords in matrix.items():
        frequency: Dict[str, int] = {}
        flag_prob = 0.0

        data = enumerate(tokens)
        for idx, line in data:
            prob, frequency = detect_prob(line, keywords, frequency)
            if prob > 0:
                applicable_weight = next(
                    (weight_multiplier[k] for k in reversed(weight_keys) if idx >= k),
                    1.0
                )
                flag_prob += prob * applicable_weight
        flag_prob = min(flag_prob, 100)

        confidence_penalty = calc_confidence(frequency, keywords)
        confidence_score = max(base_confidence_score - confidence_penalty, 0)

        length_modifier = 1.2 if len(tokens) < 300 else 1.0

        risk_scores[flag] = round(
            flag_weight
            * (flag_prob / 100)
            * (confidence_score / 100)
            * length_modifier,
            2
        )

    return risk_scores

def calc_confidence(
    observed: Dict[str, int],
    model: Dict[str, float]
    ) -> float:
    """
    Computes confidence penalty using L1 distance between
    observed keyword distribution and model probabilities.
    """
    if not observed or not model:
        return 0.0
    
    total = sum(observed.values())
    if total == 0:
        return 0.0
    
    penalty = 0.0
    for key, count in observed.items():
        if count <= 3 and " " not in key:
            continue
        observed_pct = (count / total) * 100
        expected_pct = model.get(key, 0)
        penalty += abs(expected_pct - observed_pct)
    return penalty

def detect_prob(
    tokens: list,keywords: Dict[str, float],
    frequency: Optional[Dict[str, int]] = None
    ) -> Tuple[float, Dict[str, int]]:
    """
    Detect keyword and keyphrase probabilities using
    greedy longest-match-first scanning.
    """
    if not tokens or not keywords:
        return 0.0, frequency or {}
    if frequency is None:
        frequency = {}
    probability = 0.0
    max_phrase_len = max(len(k.split()) for k in keywords)
    keyword_set = set(keywords)

    i = 0
    while i < len(tokens):
        matched = False
        for length in range(min(max_phrase_len, len(tokens) - i), 0, -1):
            phrase = " ".join(tokens[i:i + length])
            if phrase in keyword_set:
                probability += keywords[phrase]
                frequency[phrase] = frequency.get(phrase, 0) + 1
                i += length
                matched = True
                break
        if not matched:
            i += 1
    return probability, frequency

print(tokenise("Running!!!\nHello, WORLD"))