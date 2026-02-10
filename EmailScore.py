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



# Spinner animation
def spinner(stop_event, label="Scanning"):
    for ch in itertools.cycle("|/-\\"):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\r{label}... {ch}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r")


def ensure_eml(file_path: str) -> str:
    """
    If file is already .eml, return as-is.
    Otherwise convert to .eml and return new path.
    """
    if file_path.lower().endswith(".eml"):
        return file_path

    print(f"Converting to .eml: {os.path.basename(file_path)}")
    return ExtractEmail.convert_to_eml(file_path)

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
                url_flag
            ) = scoringSystem(email)

            # ---- Final weighted score ----
            final_score = 0.0

            if not attachment_flag and not url_flag:
                final_score = (
                    lang_score * 0.45 +
                    email_verify_score * 0.55
                )

            elif not attachment_flag and url_flag:
                final_score = (
                    lang_score * 0.35 +
                    email_verify_score * 0.40 +
                    url_score * 0.25
                )

            elif attachment_flag and url_flag:
                final_score = (
                    lang_score * 0.15 +
                    email_verify_score * 0.35 +
                    url_score * 0.25 +
                    doc_score * 0.25
                )

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
    
    # Grabs the files and places them in a list called "list_of_files"
    #object = DocChecking("Resources/DATASET/Project Proposal.eml")
    #list_of_files = object.files

    #If got document then call DocChecking

    # Gets the email path from an email object from the Email class
    checker = DocCheck(email.email_path)
    max_score, file_score, internet_connection, triggered_checks = checker.run_all_checks()
    dict_result = doc_calc(max_score, file_score, internet_connection, triggered_checks)

    #print(dict_result)
    return dict_result
    



def get_urlCheck_scores(email: Email):
    # If score is higher than 100 (Maximum score for URLchecking is around 190), flag it as suspicious
    # Note that self.urls.append() is used to add URLs to self.urls, if self.urls is empty self.url_score stays empty and there will be no loop

    u = UrlCheck(email.email_path)
    max_score, url_scores, internet_connection, triggered_checks = u.run_all_checks()
    result = url_calc(max_score, url_scores, internet_connection, triggered_checks)

    
    return result


def get_emailVerify_scores(email: Email):
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
    


    # ----- Attachments -----
    docPercentage_result = 0.0
    attachment_Flag = False

    call_docCheck = get_docChecking_scores(email)

    # This just checks if call_docCheck is a list or a tuple, and that its not returning an empty variable
    if isinstance(call_docCheck, (list, tuple)) and len(call_docCheck) > 0:
        docCheck_result = call_docCheck[0]

    # Similarly, this checks if call_docCheck is a dictionary
    elif isinstance(call_docCheck, dict):
        docCheck_result = call_docCheck

    else:
        docCheck_result = {}


    if docCheck_result:
        scores = [float(v) for v in docCheck_result.values()]
        num_of_attachments = len(scores)

    #     # Final percentage calculated by dividing total score by a percentage depending on how many attachments
    #     # there are, and then multiplying it by 100 again for final percentage
        if num_of_attachments > 0:
            docPercentage_result = sum(scores) / (num_of_attachments * 100) * 100
            attachment_Flag = True



    # ----- URLs -----
    urlPercentage_result = 0.0
    url_Flag = False


    # If running offline scan, URL checks are disabled
    if is_offline():

        urlPercentage_result = 0.0
        url_Flag = False

    else:

        call_urlCheck = get_urlCheck_scores(email)

        # If else statement is used to double check that no. of urls is not 0, causing an error 
        if isinstance(call_urlCheck, (list, tuple)) and len(call_urlCheck) > 0:
            urlCheck_result = call_urlCheck[0]

        elif isinstance(call_urlCheck, dict):
            urlCheck_result = call_urlCheck

        else:
            urlCheck_result = {}

        if urlCheck_result:
            scores = [float(v) for v in urlCheck_result.values()]
            num_of_urls = len(scores)

            if num_of_urls > 0:
                urlPercentage_result = sum(scores) / (num_of_urls * 100) * 100
                url_Flag = True






    #------------------------------------------ Email Verify section --------------------------------------#
    emailVerify_Dict = get_emailVerify_scores(email)

    emailVerify_risk = emailVerify_Dict.get("risk_percentage", 0.0)

    #------------------------------------------ Language Analysis section --------------------------------------#   
    # Default weightage
    varied_weightage = 45

    # 45% Language, 55% email, urls no, attachment no
    if attachment_Flag == False and url_Flag == False:
        varied_weightage = 45


    # 35% Language, 40% email, 25% Url, attachment no
    elif attachment_Flag == False and url_Flag == True:
        varied_weightage = 35


    # 15%, language, 35% email, 25% url, 25% attachment
    elif attachment_Flag == True and url_Flag == True:
        varied_weightage = 15


    # This if else statement checks if the email is empty, doesn't have any text
    if email.text and email.text.strip():

        matrix = init_keyword_matrix()
        langAnalysis_dict = email_language_risk(email=email, 
                                                matrix=matrix, 
                                                total_weightage = varied_weightage, 
                                                base_confidence_score=100
                                                )
        total_values = 0.0

        for values in langAnalysis_dict.values():
            total_values = total_values + values

        langAnalysis_total_percentage = (total_values / varied_weightage) * 100
    
    else:
        langAnalysis_total_percentage = 0.0


    return (
        docPercentage_result, 
        urlPercentage_result, 
        emailVerify_risk, 
        langAnalysis_total_percentage,
        attachment_Flag,
        url_Flag
    )


if __name__ == "__main__":

    batch_scan_eml_folder("Resources/DATASET")


