# 45% Language, 55% email, urls no, attachment no
# 35% Language, 40% email, 25% Url, attachment no
# 15% language, 35% email, 25% url, 25% attachment

# The second DocChecking is the class of the folder DocChecking
from DocChecking.DocCheck import *
# This line imports risk_score_calculate as a function named doc_calc
from DocChecking.DocCheck import risk_score_calculate as doc_calc
from URLChecking.UrlCheck import UrlCheck
from URLChecking.UrlCheck import risk_score_calculate as url_calc
from EmailVerify.main import EmailVerifier, Email
from typing import Any, Dict, List, Tuple
from LangAnalysis.main import *
from LangAnalysis.email_extract import Email as ExtractEmail

# animation loading spinner
import threading
import itertools
import sys
import time
# Blocks internet
import socket
_original_socket = socket.socket

def block_internet(*args, **kwargs):
    raise RuntimeError("Internet access is disabled")

def enable_offline_mode():
    socket.socket = block_internet

def disable_offline_mode():
    socket.socket = _original_socket

# removes any temporary files in temp folder
def clear_temp_files():
    temp_path = "Resources/TEMP_FILES"

    if not os.path.exists(temp_path):
        return

    for filename in os.listdir(temp_path):
        file_path = os.path.join(temp_path, filename)
        if os.path.isfile(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass

# Spinner animation
def spinner(stop_event, label="Scanning"):
    for ch in itertools.cycle("|/-\\"):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\r{label}... {ch}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r")


# This function just double checks if the file that is not .eml (email blobs) have already
# been converted to .eml before, preventing duplicates
def ensure_eml(file_path: str) -> str:
    if file_path.lower().endswith(".eml"):
        return file_path

    eml_path = os.path.splitext(file_path)[0] + ".eml"
    if os.path.exists(eml_path):
        return eml_path

    return ExtractEmail.convert_to_eml(file_path)

# Goes through a folder and scans each file one by one
def batch_scan_eml_folder(folder_path: str):
    if not os.path.isdir(folder_path):
        print(f"Invalid folder path: {folder_path}")
        return

    # Scans all files, regardless of extension
    all_files = [
        f for f in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, f))
    ]

    if not all_files:
        print("No appropriate email format files found in folder.")
        return

    print(f"Found {len(all_files)} email(s) to scan.\n")

    for filename in all_files:
        original_path = os.path.join(folder_path, filename)
        eml_path = ensure_eml(original_path)

        print("=" * 70)
        print(f"Scanning: {filename}")


        # Animation stuff
        stop_event = threading.Event()
        t = threading.Thread(
            target=spinner,
            args=(stop_event, f"Scanning {filename}")
        )
        t.start()



        try:
            # Create Email object
            email = Email(eml_path)

            # ---- Grabbing variables from scoringSystem() ----
            (
                doc_score,
                url_score,
                email_verify_score,
                lang_score,
                attachment_flag,
                url_flag,
                final_score,
                # Details is still needed here for unpacking, otherwise python will throw an error
                # Details is not used for CLI, only gui
                details
            ) = scoringSystem(email)



        except Exception as e:
            stop_event.set()
            t.join()
            print(f"\rError scanning {filename}: {e}")
            continue

        # ---- Stop spinner cleanly ----
        stop_event.set()
        t.join()

        # ---- Output ----
        print(f"From: {email.sender}")
        print(f"Subject: {email.subject}")
        print(f"Final Risk Score: {final_score:.2f}%")


    print("\nBatch scan complete")

def get_docChecking_scores(email: Email):
    # Gets the email path from an email object from the Email class
    if email.attachment_header:
        checker = DocCheck(email.email_path)
    else:
        return 0, {}
    max_score, file_score, internet_connection, triggered_checks = checker.run_all_checks()

    final_file_score, triggered_checks, ranked_files = doc_calc(
        max_score,
        file_score,
        internet_connection,
        triggered_checks
    )
    if isinstance(final_file_score, (list, tuple)) and len(final_file_score) > 0:
        docCheck_result = final_file_score[0]
    elif isinstance(final_file_score, dict):
        docCheck_result = final_file_score
    else:
        docCheck_result = {}
    scores = _extract_numeric_scores(docCheck_result)
    if scores:
        doc_score = sum(scores) / len(scores) 
    else:
        doc_score = 0
    return doc_score, docCheck_result
    

def get_urlCheck_scores(email: Email):
    # If score is higher than 100 (Maximum score for URLchecking is around 190), flag it as suspicious
    # Note that self.urls.append() is used to add URLs to self.urls, if self.urls is empty self.url_score stays empty and there will be no loop

    # Initialize UrlCheck object
    url_checker = UrlCheck(email.email_path)

    # Run all checks (returns connectivity status and triggered checks)
    connectivity, triggered_checks = url_checker.run_all_checks()

    # Calculate URL risk scores
    ranked_url_scores, triggered_checks = url_calc(connectivity, triggered_checks)

    url_scores: List[float] = []

    # Common case: list of (url, score)
    if isinstance(ranked_url_scores, (list, tuple)):
        for item in ranked_url_scores:
            if isinstance(item, tuple) and len(item) == 2:
                try:
                    url_scores.append(float(item[1]))
                except (TypeError, ValueError):
                    pass
            elif isinstance(item, dict):
                # fallback if per-url dicts appear
                url_scores.extend(_extract_numeric_scores(item))
            else:
                # fallback if a raw numeric list appears
                try:
                    url_scores.append(float(item))
                except (TypeError, ValueError):
                    pass

    # Alternate case: dict of {url: score}
    elif isinstance(ranked_url_scores, dict):
        url_scores = _extract_numeric_scores(ranked_url_scores)

    if url_scores:
        total_score = sum(url_scores) / len(url_scores)
    else:
        total_score = 0
    return total_score, url_scores


def get_emailVerify_scores(email: Email):
    # edit_distance() is used for detecting sus typos like g00gle.com instead of google.com (Levenshtein edit distance)
    # To use the EmailVerifier class you need to give normalize_domain() an EmailVerifier object, not a string
    verifier = EmailVerifier(email)
    
    result = verifier.run_verification()
    email_score = float(result.get("risk_percentage", 0.0) or 0.0)
    return email_score,result
    

################################################################################################################

def is_offline():
    return socket.socket == block_internet


def _extract_numeric_scores(obj: Any) -> List[float]:
    """
    Extract floats from dict/list/tuple structures.
    Intended inputs:
      - dict of {something: score}
      - list/tuple of numbers
      - list of dicts
      - list of (thing, score) tuples (handled in URL section separately if needed)
    """
    scores: List[float] = []

    if obj is None:
        return scores

    if isinstance(obj, dict):
        for v in obj.values():
            try:
                scores.append(float(v))
            except (TypeError, ValueError):
                pass
        return scores

    if isinstance(obj, (list, tuple)):
        for item in obj:
            if isinstance(item, dict):
                for v in item.values():
                    try:
                        scores.append(float(v))
                    except (TypeError, ValueError):
                        pass
            elif isinstance(item, (int, float, str)):
                try:
                    scores.append(float(item))
                except (TypeError, ValueError):
                    pass
            # tuples like (url, score) are handled in the URL section
        return scores

    # single scalar
    if isinstance(obj, (int, float, str)):
        try:
            scores.append(float(obj))
        except (TypeError, ValueError):
            pass

    return scores

def scoringSystem(email:Email, pass_threshold:float = 0.35,is_offline:bool =True):

    #get feature tunction results
    body_exists = bool(email.text and email.text.strip())
    if is_offline:
        url_score, url_result = 0, None
    else:
        url_score,url_result = get_urlCheck_scores(email)
    doc_score, doc_result = get_docChecking_scores(email)
    email_score,email_result = get_emailVerify_scores(email)
    matrix = init_keyword_matrix()
    language_result = email_language_risk(email=email,matrix=matrix) if body_exists else None 

    if language_result:
        base_total = sum(float(v) for v in language_result.values())
        flags = 0
        for v in language_result.values():
            if float(v) * 2 > (100 / 4):
                flags += 1

        bonus = 0.0
        if flags >= 2:
            bonus = (100 / 4) * flags

        language_score = base_total + bonus

    #get weights
    attachment_weight = 0.0
    url_weight = 0.0
    email_weight = 0.35
    language_weight = 0.15

    if doc_result and url_result:
        url_weight = 0.25
        attachment_weight = 0.25
    elif doc_result:
        attachment_weight = 0.25
        email_weight += 0.05
        language_weight += 0.20
    elif url_result:
        url_weight = 0.25
        email_weight += 0.05
        language_weight += 0.20
    else:
        email_weight = 0.55
        language_weight = 0.45
        url_weight = 0.0
    
    if not body_exists:
        num_weights = 0
        if url_weight:
            num_weights += 1
        if attachment_weight:
            num_weights += 1
        email_weight += language_weight/num_weights
        url_weight += language_weight/num_weights
        attachment_weight += language_weight/num_weights


    wsum = email_weight + language_weight + url_weight + attachment_weight
    if wsum > 0 and abs(wsum - 1.0) > 1e-9:
        email_weight /= wsum
        language_weight /= wsum
        url_weight /= wsum
        attachment_weight /= wsum

    if language_score/100 > pass_threshold:
        language_score = 100
    if url_score/100 > pass_threshold:
        url_score = 100
    if email_score/100 > pass_threshold:
        email_score = 100
    if doc_score/100 > pass_threshold:
        doc_score = 100

    final_score = (
        language_score * language_weight +
        email_score * email_weight +
        url_score * url_weight +
        doc_score * attachment_weight
    )
    output = {
        "email_result":email_result,
        "url_result":url_result,
        "doc_result":doc_result,
        'language_result':language_result,
        "email_score":email_score,
        "url_score":url_score,
        "doc_score":doc_score,
        "language_score":language_score,
        "final_score": final_score
    }
    return output

if __name__ == "__main__":
    batch_scan_eml_folder("Resources/TESTCASES")
    




