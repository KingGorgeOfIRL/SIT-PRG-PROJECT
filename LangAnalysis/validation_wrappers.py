from typing import Dict, List, Optional,Tuple,Any
from functools import lru_cache
from email_extract import Email
from main import tokenise, detect_prob, calc_confidence,get_multipliers

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

def safe_get_multipliers() -> Tuple[Dict[int, float], int, int, List[int]]:
    try:
        weight_multiplier, suspect_length, suspect_line_num = get_multipliers()
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
