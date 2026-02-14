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
    #print("\nStart of get_docChecking_scores ")

    # Gets the email path from an email object from the Email class
    checker = DocCheck(email.email_path)

    max_score, file_score, internet_connection, triggered_checks = checker.run_all_checks()

    final_file_score, triggered_checks, ranked_files = doc_calc(
        max_score,
        file_score,
        internet_connection,
        triggered_checks
    )

    print(final_file_score)
    return final_file_score
    

def get_urlCheck_scores(email: Email):
    #print("\nStart of get_urlCheck_scores ")
    # If score is higher than 100 (Maximum score for URLchecking is around 190), flag it as suspicious
    # Note that self.urls.append() is used to add URLs to self.urls, if self.urls is empty self.url_score stays empty and there will be no loop

    # Initialize UrlCheck object
    url_checker = UrlCheck(email.email_path)

    # Run all checks (returns connectivity status and triggered checks)
    connectivity, triggered_checks = url_checker.run_all_checks()

    # Calculate URL risk scores
    ranked_url_scores, triggered_checks = url_calc(connectivity, triggered_checks)

    print(ranked_url_scores)
    return ranked_url_scores, triggered_checks


def get_emailVerify_scores(email: Email):
    #print("\nStart of get_emailVerify_scores ")
    # edit_distance() is used for detecting sus typos like g00gle.com instead of google.com (Levenshtein edit distance)
    # To use the EmailVerifier class you need to give normalize_domain() an EmailVerifier object, not a string
    verifier = EmailVerifier(email)
    
    result = verifier.run_verification()

    return result
    

################################################################################################################

def is_offline():
    return socket.socket == block_internet


def scoringSystem(email: Email):

    #------------------------------------- Doc Checking & URL Check section ----------------------------#
    
    clear_temp_files()

    # Details dictionary is used for logging
    details = {} 

    # ----- Attachments -----
    docPercentage_result = 0.0
    attachment_Flag = False


    call_docCheck = get_docChecking_scores(email)
    details["doc_check_raw"] = call_docCheck


    # This just checks if call_docCheck is a list or a tuple, and that its not returning an empty variable
    if isinstance(call_docCheck, (list, tuple)) and len(call_docCheck) > 0:
        docCheck_result = call_docCheck[0]

    # Similarly, this checks if call_docCheck is a dictionary
    elif isinstance(call_docCheck, dict):
        docCheck_result = call_docCheck

    else:
        docCheck_result = {}


    if docCheck_result:
        if isinstance(docCheck_result, dict):
            scores = [float(v) for v in docCheck_result.values()]
        elif isinstance(docCheck_result, list):
            # Convert list of numbers or dicts to floats
            scores = []
            for item in docCheck_result:
                if isinstance(item, dict):
                    scores.extend(float(v) for v in item.values())
                else:
                    scores.append(float(item))
        else:
            scores = []

        num_of_attachments = len(scores)
    #     # Final percentage calculated by dividing total score by a percentage depending on how many attachments
    #     # there are, and then multiplying it by 100 again for final percentage
        if num_of_attachments > 0:
            docPercentage_result = sum(scores) / (num_of_attachments * 100) * 100
            attachment_Flag = True


    details["doc_percentage"] = docPercentage_result
    details["attachment_flag"] = attachment_Flag


        # ----- URLs -----
    urlPercentage_result = 0.0
    url_Flag = False

    # If running offline scan, URL checks are disabled
    if is_offline():
        urlPercentage_result = 0.0
        url_Flag = False

    else:
        call_urlCheck = get_urlCheck_scores(email)
        details["url_check_raw"] = call_urlCheck

        # Extract numeric scores safely
        scores = []

        if isinstance(call_urlCheck, (list, tuple)) and len(call_urlCheck) > 0:
            for item in call_urlCheck:
                if isinstance(item, tuple) and len(item) == 2:
                    # item = (url, score)
                    try:
                        scores.append(float(item[1]))
                    except (ValueError, TypeError):
                        pass
                elif isinstance(item, (int, float, str)):
                    try:
                        scores.append(float(item))
                    except (ValueError, TypeError):
                        pass
        elif isinstance(call_urlCheck, dict):
            for v in call_urlCheck.values():
                try:
                    scores.append(float(v))
                except (ValueError, TypeError):
                    pass

        # Calculate final percentage
        num_of_urls = len(scores)
        if num_of_urls > 0:
            urlPercentage_result = sum(scores) / (num_of_urls * 100) * 100
            url_Flag = True

    details["url_percentage"] = urlPercentage_result
    details["url_flag"] = url_Flag






    #------------------------------------------ Email Verify section --------------------------------------#
    
    emailVerify_Dict = get_emailVerify_scores(email)
    details["email_verify_raw"] = emailVerify_Dict

    emailVerify_risk = emailVerify_Dict.get("risk_percentage", 0.0)
    details["email_verify_risk"] = emailVerify_risk

    #------------------------------------------ Language Analysis and weightage section --------------------------------------#   
    langAnalysis_dict = {}

    score_adjustments = {
        "Document_Percentage" : 50.0,
        "url_percentage" : 20.0,
        "Email_Verify_Percentage" : 6.0,
        "Language_Analysis_Percentage" : 10.0,
    }

    # This if else statement checks if the email is empty, doesn't have any text
    langAnalysis_total_percentage = 0.0
    if email.text and email.text.strip():
        total_weightage = 100
        matrix = init_keyword_matrix()
        langAnalysis_dict = email_language_risk(email=email, 
                                                matrix=matrix, 
                                                total_weightage = total_weightage, 
                                                base_confidence_score=100
                                                )

        langAnalysis_total_percentage = sum(langAnalysis_dict.values())
        flags = 0
        for flag in langAnalysis_dict:
            if langAnalysis_dict[flag] * 2 > (total_weightage/4): 
                flags += 1
            langAnalysis_total_percentage += langAnalysis_dict[flag]
        if flags >= 2:
            langAnalysis_total_percentage += (total_weightage/4) * flags

    details["language_raw"] = langAnalysis_dict
    details["language_percentage"] = langAnalysis_total_percentage

    # -------------------------------- Final Weighted Score -------------------------------- #

    body_exists = bool(email.text and email.text.strip())
    attachment_only = attachment_Flag and not body_exists and not url_Flag

    final_score = 0.0
    attachment_weight = 0
    email_weight = 0
    language_weight = 0
    url_weight = 0
    if attachment_only:
        attachment_weight = 0.7
        email_weight = 0.3
    elif not attachment_Flag and not url_Flag:
        language_weight = 0.45
        email_weight = 0.3
    elif not attachment_Flag and url_Flag:
        language_weight = 0.35
        email_weight = 0.4
        url_weight = 0.25
    elif attachment_weight and url_weight:
        language_weight = 0.15
        email_weight = 0.35
        url_weight = 0.25
        attachment_weight = 0.25

    pass_threshold = 0.5
    if docPercentage_result >= (attachment_weight * pass_threshold):
        docPercentage_result = 100
    elif urlPercentage_result >= (url_weight * pass_threshold):
        urlPercentage_result = 100    
    elif emailVerify_risk >= (email_weight * pass_threshold):
        emailVerify_risk = 100
    elif langAnalysis_total_percentage >= (language_weight * pass_threshold):
        langAnalysis_total_percentage = 100

    final_score = (
        langAnalysis_total_percentage * language_weight +
        emailVerify_risk * email_weight +
        urlPercentage_result * url_weight +
        docPercentage_result * attachment_weight
    )


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
    




