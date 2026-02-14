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
    checker = DocCheck(email.email_path)

    max_score, file_score, internet_connection, triggered_checks = checker.run_all_checks()

    final_file_score, triggered_checks, ranked_files = doc_calc(
        max_score,
        file_score,
        internet_connection,
        triggered_checks
    )

    return final_file_score
    

def get_urlCheck_scores(email: Email):
    # If score is higher than 100 (Maximum score for URLchecking is around 190), flag it as suspicious
    # Note that self.urls.append() is used to add URLs to self.urls, if self.urls is empty self.url_score stays empty and there will be no loop

    # Initialize UrlCheck object
    url_checker = UrlCheck(email.email_path)

    # Run all checks (returns connectivity status and triggered checks)
    connectivity, triggered_checks = url_checker.run_all_checks()

    # Calculate URL risk scores
    ranked_url_scores, triggered_checks = url_calc(connectivity, triggered_checks)
    return ranked_url_scores, triggered_checks


def get_emailVerify_scores(email: Email):
    # edit_distance() is used for detecting sus typos like g00gle.com instead of google.com (Levenshtein edit distance)
    # To use the EmailVerifier class you need to give normalize_domain() an EmailVerifier object, not a string
    verifier = EmailVerifier(email)
    
    result = verifier.run_verification()
    return result
    

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


def scoringSystem(email: Email, pass_threshold = 0.35):
    #------------------------------------- Doc Checking & URL Check section ----------------------------#

    clear_temp_files()
    details: Dict[str, Any] = {}

    # ----- Attachments -----
    docPercentage_result = 0.0
    attachment_Flag = False

    call_docCheck = get_docChecking_scores(email)
    details["doc_check_raw"] = call_docCheck

    # Normalize docCheck_result into something score-extractable
    if isinstance(call_docCheck, (list, tuple)) and len(call_docCheck) > 0:
        docCheck_result = call_docCheck[0]
    elif isinstance(call_docCheck, dict):
        docCheck_result = call_docCheck
    else:
        docCheck_result = {}

    scores = _extract_numeric_scores(docCheck_result)
    if scores:
        docPercentage_result = sum(scores) / len(scores)  # average 0..100
        attachment_Flag = True

    details["doc_percentage"] = docPercentage_result
    details["attachment_flag"] = attachment_Flag

    # ----- URLs -----
    urlPercentage_result = 0.0
    url_Flag = False

    if is_offline():
        details["url_check_raw"] = None
        urlPercentage_result = 0.0
        url_Flag = False
    else:
        call_urlCheck = get_urlCheck_scores(email)
        details["url_check_raw"] = call_urlCheck

        url_scores: List[float] = []

        if isinstance(call_urlCheck, (list, tuple)) and len(call_urlCheck) > 0:
            for item in call_urlCheck:
                # item could be (url, score)
                if isinstance(item, tuple) and len(item) == 2:
                    try:
                        url_scores.append(float(item[1]))
                    except (ValueError, TypeError):
                        pass
                else:
                    # fallback: try to parse item as numeric
                    try:
                        url_scores.append(float(item))
                    except (ValueError, TypeError):
                        pass

        elif isinstance(call_urlCheck, dict):
            for v in call_urlCheck.values():
                try:
                    url_scores.append(float(v))
                except (ValueError, TypeError):
                    pass

        if url_scores:
            urlPercentage_result = sum(url_scores) / len(url_scores)  # average 0..100
            url_Flag = True

    details["url_percentage"] = urlPercentage_result
    details["url_flag"] = url_Flag

    #------------------------------------------ Email Verify section --------------------------------------#

    emailVerify_Dict = get_emailVerify_scores(email) or {}
    details["email_verify_raw"] = emailVerify_Dict

    emailVerify_risk = float(emailVerify_Dict.get("risk_percentage", 0.0) or 0.0)
    details["email_verify_risk"] = emailVerify_risk

    #------------------------------------------ Language Analysis and weightage section --------------------------------------#

    langAnalysis_dict: Dict[str, float] = {}
    langAnalysis_total_percentage = 0.0

    body_exists = bool(email.text and email.text.strip())
    if body_exists:
        total_weightage = 100.0
        matrix = init_keyword_matrix()

        langAnalysis_dict = email_language_risk(
            email=email,
            matrix=matrix,
            total_weightage=total_weightage,
            base_confidence_score=100
        ) or {}

        # Base total is just the sum once
        base_total = sum(float(v) for v in langAnalysis_dict.values())

        # Flag logic (kept conceptually similar to yours, but without double-counting)
        flags = 0
        for v in langAnalysis_dict.values():
            if float(v) * 2 > (total_weightage / 4):
                flags += 1

        bonus = 0.0
        if flags >= 2:
            bonus = (total_weightage / 4) * flags

        langAnalysis_total_percentage = base_total + bonus

    details["language_raw"] = langAnalysis_dict
    details["language_percentage"] = langAnalysis_total_percentage

    # -------------------------------- Final Weighted Score -------------------------------- #

    # Default weights
    attachment_weight = 0.0
    url_weight = 0.0
    email_weight = 0.35
    language_weight = 0.15

    if not body_exists:
        email_weight = 0.0
        language_weight = 0.0
        attachment_weight = 1.0
        url_weight = 0.0
    elif attachment_Flag and url_Flag:
        url_weight = 0.25
        attachment_weight = 0.25
    elif attachment_Flag:
        attachment_weight = 0.25
        email_weight += 0.05
        language_weight += 0.20
    elif url_Flag:
        url_weight = 0.25
        email_weight += 0.05
        language_weight += 0.20
    else:
        email_weight = 0.55
        language_weight = 0.45
        url_weight = 0.0
        attachment_weight = 0.0

    # Optional safety: normalize in case future edits introduce drift
    wsum = email_weight + language_weight + url_weight + attachment_weight
    if wsum > 0 and abs(wsum - 1.0) > 1e-9:
        email_weight /= wsum
        language_weight /= wsum
        url_weight /= wsum
        attachment_weight /= wsum

    details["weights"] = {
        "language_weight": language_weight,
        "email_weight": email_weight,
        "url_weight": url_weight,
        "attachment_weight": attachment_weight,
    }

    # Threshold boosting: boost the strongest contributor if it clears pass_threshold
    pass_threshold = 0.35

    contributions = {
        "language": (langAnalysis_total_percentage / 100.0) * language_weight if body_exists else 0.0,
        "email_verify": (emailVerify_risk / 100.0) * email_weight if body_exists else 0.0,
        "url": (urlPercentage_result / 100.0) * url_weight if url_Flag else 0.0,
        "doc": (docPercentage_result / 100.0) * attachment_weight if attachment_Flag else 0.0,
    }
    details["contributions_preboost"] = contributions

    # Choose max contributor to boost (instead of fixed if/elif order)
    max_key = max(contributions, key=contributions.get)
    if contributions[max_key] >= pass_threshold:
        if max_key == "doc":
            docPercentage_result = 100.0
        elif max_key == "url":
            urlPercentage_result = 100.0
        elif max_key == "email_verify":
            emailVerify_risk = 100.0
        elif max_key == "language":
            langAnalysis_total_percentage = 100.0

    # Final score
    final_score = (
        langAnalysis_total_percentage * language_weight +
        emailVerify_risk * email_weight +
        urlPercentage_result * url_weight +
        docPercentage_result * attachment_weight
    )
    details["final_score"] = final_score

    return (
        docPercentage_result,
        urlPercentage_result,
        emailVerify_risk,
        langAnalysis_total_percentage,
        attachment_Flag,
        url_Flag,
        final_score,
        details
    )

if __name__ == "__main__":
    batch_scan_eml_folder("Resources/TESTCASES")
    




