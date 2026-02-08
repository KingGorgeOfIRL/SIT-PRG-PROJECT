import os
from typing import Dict, List, Optional,Tuple, Any
from functools import lru_cache
import re
from LangAnalysis.email_extract import Email,init_file

def safe_detect_prob(
    line_tokens: List[str],
    keywords: Dict[str, float],
    frequency: Dict[str, int]
) -> Tuple[float, Dict[str, int]]:
    try:
        prob, freq = detect_prob(line_tokens, keywords, frequency)
    except Exception:
        # Degrade-safe: treat as no match for this line
        return 0.0, frequency

    if not isinstance(prob, (int, float)) or not isinstance(freq, dict):
        return 0.0, frequency

    return float(prob), freq

def safe_confidence_penalty(frequency: Dict[str, int], keywords: Dict[str, float]) -> float:
    try:
        penalty = calc_confidence(frequency, keywords)
    except Exception:
        return 0.0
    return float(penalty) if isinstance(penalty, (int, float)) else 0.0

def safe_get_multipliers(title_weight:int = 40,suspect_length:int=300) -> Tuple[Dict[int, float], int, int, List[int]]:
    try:
        weight_multiplier, suspect_length, suspect_line_num = get_multipliers(title_weight,suspect_length)
    except Exception as e:
        raise RuntimeError("_get_multipliers() failed") from e

    if not isinstance(weight_multiplier, dict) or not weight_multiplier:
        raise ValueError("weight_multiplier must be a non-empty dict")
    if not all(isinstance(k, int) for k in weight_multiplier):
        raise TypeError("weight_multiplier keys must be ints (line indices)")
    if not all(isinstance(v, (int, float)) for v in weight_multiplier.values()):
        raise TypeError("weight_multiplier values must be numeric")

    if not isinstance(suspect_length, int) or suspect_length <= 0:
        raise ValueError("suspect_length must be a positive int")
    if not isinstance(suspect_line_num, int) or suspect_line_num <= 0:
        raise ValueError("suspect_line_num must be a positive int")

    rev_weight_keys = sorted(weight_multiplier.keys(), reverse=True)
    return weight_multiplier, suspect_length, suspect_line_num, rev_weight_keys

def safe_get_text(email: Optional["Email"], body: Optional[str], title: Optional[str]) -> Tuple[str, str, str]:
    if email is not None:
        subject = getattr(email, "subject", "") or ""
        body_text = getattr(email, "text", "") or ""
    else:
        subject = title or ""
        body_text = body or ""
    raw_text = f"{subject}\n{body_text}"
    return subject, body_text, raw_text

def line_weight(idx: int, weight_multiplier: Dict[int, float], rev_weight_keys: List[int]) -> float:
    # Pick the largest threshold <= idx
    for k in rev_weight_keys:
        if idx >= k:
            return float(weight_multiplier[k])
    return 1.0

def validate_matrix(matrix: Any) -> Dict[str, Dict[str, float]]:
    if not isinstance(matrix, dict) or not matrix:
        raise ValueError("matrix must be a non-empty Dict[str, Dict[str, float]]")

    for flag, keywords in matrix.items():
        if not isinstance(flag, str):
            raise TypeError("matrix keys (flag names) must be strings")
        if not isinstance(keywords, dict):
            raise TypeError(f"matrix['{flag}'] must be a Dict[str, float]")
        for k, v in keywords.items():
            if not isinstance(k, str):
                raise TypeError(f"Keyword key in flag '{flag}' must be a string")
            if not isinstance(v, (int, float)):
                raise TypeError(f"Keyword weight for '{k}' in flag '{flag}' must be numeric")
    return matrix

def safe_tokenise(raw_text: str) -> List[List[str]]:
    try:
        tokens = tokenise(raw_text)
    except Exception as e:
        raise RuntimeError("tokenise() failed") from e

    if not isinstance(tokens, list):
        raise TypeError("tokenise() must return List[List[str]]")

    for line in tokens:
        if not isinstance(line, list):
            raise TypeError("tokenise() must return List[List[str]] (each line must be a list)")
        for tok in line:
            if not isinstance(tok, str):
                raise TypeError("tokenise() must return List[List[str]] containing only strings")

    return tokens


def _printable(string:str) -> bool:
    return string.isprintable()

@lru_cache(maxsize=1)
def get_lemmatizer_wordlist() -> Dict[str, str]:
    """
    Load and cache the lemmatization wordlist.
    Cached after first call.
    """
    try:
        return init_file(
            path="Resources/WORDLISTS/tokenisation/lemmatization-en.txt",
            inverse=True,
            encoding="utf-8-sig"
        )
    except Exception as e:
        raise RuntimeError(
            "Failed to load lemmatization wordlist"
        ) from e

@lru_cache(maxsize=64)
def get_multipliers(title_weight:int = 40,suspect_length:int=300) -> tuple[Dict[int,float],int,int]:
    num_lines = int(suspect_length / 10)

    if not (0 <= title_weight <= 100) or suspect_length <= 0:
        raise ValueError("inputs out of value bounds")

    num_lines = max(1, suspect_length // 10)

    # Number of decay steps (at least 1)
    steps = max(1, (title_weight // 10) - 1)

    # Step size in lines (at least 1)
    step_size = max(1, num_lines // steps)

    line_multiplier: Dict[int, float] = {0: 1.0 + (title_weight / 100.0)}

    # Build decreasing multipliers
    for step_idx in range(1, steps + 2):
        line_num = step_idx * step_size
        mult = 1.0 + ((title_weight / 10.0) - step_idx) / 10.0
        line_multiplier[line_num] = max(0.0, mult)  # optional clamp

    return line_multiplier, suspect_length, num_lines

def tokenise(text: str) -> List[List[str]]:
    #Strip, simplify, and tokenise text using a brute-force wordlist lemmatizer.
    tokenised: List[str] = []
    wordlist = get_lemmatizer_wordlist()
    if not text:
        return tokenised
    
    lines = text.split("\n")
    for raw_line in lines:
        words = list(filter(_printable, raw_line.split()))
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

def init_keyword_matrix(
    keyword_folder_path:str="Resources/WORDLISTS/language_analysis"
    ) -> Dict[str, Dict[str, float]]:
    """
    Load keyword probability models from a directory of text files.
    Each file represents a risk flag category.
    """
    matrix: Dict[str, Dict[str, float]] = {}

    for dirpath, _, filenames in os.walk(keyword_folder_path):
        for filename in filenames:
            flag_name = filename.rsplit(".", 1)[0]
            keywords = init_file(os.path.join(dirpath, filename))
            
            flag_keywords: Dict[str, float] = {}
            for key, value in keywords.items():
                # Tokenise keyword/keyphrase and normalise to space-separated form
                tokenised_key = tokenise(key)
                if not tokenised_key:
                    continue

                # Join all lines (keywords should normally be single-line)
                flattened_tokens = [tok for line in tokenised_key for tok in line]
                if not flattened_tokens:
                    continue
                normalised_key = " ".join(tokenised_key[0])

                # Store probability as float
                normalised_key = " ".join(flattened_tokens)
                flag_keywords[normalised_key] = float(value)

            matrix[flag_name] = flag_keywords
    return matrix

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

def email_language_risk(
    email: Optional["Email"] = None,
    body: Optional[str] = None,
    title: Optional[str] = None,
    matrix: Optional[Dict[str, Dict[str, float]]] = None,
    total_weightage: int = 40,base_confidence_score: int = 100
) -> Dict[str, float]:
    #Calculate per-flag language risk scores for an email.

    if not isinstance(total_weightage, (int, float)) or total_weightage <= 0:
        raise ValueError("total_weightage must be a positive number")
    if not isinstance(base_confidence_score, (int, float)) or base_confidence_score < 0:
        raise ValueError("base_confidence_score must be >= 0")
    
    matrix = validate_matrix(matrix)

    _, _, raw_text = safe_get_text(email, body, title)
    tokens = safe_tokenise(raw_text)

    weight_multiplier, suspect_length, suspect_line_num, rev_weight_keys = safe_get_multipliers()

    flag_weight = float(total_weightage) / float(len(matrix))
    risk_scores: Dict[str, float] = {}

    num_lines = len(tokens)
    char_len = len(raw_text)

    for flag, keywords in matrix.items():
        frequency: Dict[str, int] = {}
        flag_prob = 0.0

        for idx, line in enumerate(tokens):
            prob, frequency = safe_detect_prob(line, keywords, frequency)
            if prob <= 0:
                continue
            flag_prob += prob * line_weight(idx, weight_multiplier, rev_weight_keys)
        flag_prob = max(0.0, min(flag_prob, 100.0))

        confidence_penalty = safe_confidence_penalty(frequency, keywords)
        confidence_score = max(0.0, float(base_confidence_score) - confidence_penalty)
        confidence_score = min(confidence_score, 100.0)

        length_modifier = 1.2 if (char_len < suspect_length or num_lines < suspect_line_num) else 1.0

        risk_scores[flag] = round(
            flag_weight
            * (flag_prob / 100)
            * (confidence_score / 100)
            * length_modifier,
            2
        )

    return risk_scores

if __name__ == "__main__":
    email = Email("Resources/DATASET/sitletter.eml")
    matrix = init_keyword_matrix()
    result = email_language_risk(email=email,
                                 matrix=matrix,
                                 total_weightage=40,
                                 base_confidence_score=100)
    print(result)
