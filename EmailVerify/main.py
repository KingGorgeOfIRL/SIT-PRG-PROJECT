from os import listdir, remove, path
from zipfile import ZipFile
from email.utils import parsedate_to_datetime, parseaddr

from email import policy
from email.parser import Parser, HeaderParser
from html.parser import HTMLParser
from io import StringIO
import base64

class MLStripper(HTMLParser):
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

def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()

class Email:
    def __init__(self,email_path:str):
        self.email_path:str = email_path
        headers = self.__extract_headers()
        extract = self.__extract_body()
        self.text:str = extract[0]
        self.attachment_header = extract[1]
        self.raw = extract[2]
        self.subject:str = headers['Subject'] 
        self.sender:str = headers['From'] 
        self.headers:dict = headers 
        
    #extracts all body text free of HTML tags
    def __extract_body(self):
        with open(self.email_path,'r') as file:
            raw = Parser(policy=policy.default).parse(file)
        attachment_header = []
        plain_text:str = None
        for part in raw.walk():
            if part.is_attachment():
                if "base64" in part.get("Content-Transfer-Encoding"):
                    attachment_header.append(self.__bs64_save_attachments(part.get_payload(),part.get('Content-Disposition')))
                else:
                    print("cannot save file. not the right encoding")
            elif 'text/plain' in part.get('Content-Type'):
                plain_text = str(part.get_payload(decode=True))
            elif 'text/html' in part.get('Content-Type'):
                plain_text = strip_tags(str(part.get_payload(decode=True).decode("utf-8")))
        
        return plain_text,attachment_header,raw
    
    #extract all email headers as a dictionary
    def __extract_headers(self):
        with open(self.email_path,'r') as file:
            raw = HeaderParser().parse(file)
        raw_dict = {}
        for item in raw.items():
            raw_dict[item[0]] = item[1]
        return raw_dict
    
    def __bs64_save_attachments(self,base64str:str,header_data:str,output_path:str="Resources/TEMP_FILES"):
        meta_data:dict = {}
        name = "temp_file"

        #extracts Meta-Data
        for field in str(header_data).split('; '):
            if '=' not in field:
                continue
            field = field.split('"')
            meta_data[field[0]] = field[1]
            if "name" in field[0]:
                name = field[1]
        
        #removes Mime Header
        if "," in base64str:
            base64str = base64str.split(",", 1)[1]
        
        #writes bytes to file
        file_bytes = base64.b64decode(base64str)
        with open(f"{output_path}/{name}", "wb") as f:
            f.write(file_bytes)
        return meta_data

    def __repr__(self):
        return f"Email<Subject:{self.subject},Sender:{self.sender}>"


class EmailVerifier:
    def __init__(self, email):
        self.email = email

        self.risk_score = 0
        self.flags = {}
        # Loads trusted emails, domains and known companies from files
        self.trusted_emails = self.load_wordlist("resources/WORDLISTS/trusted_emails.txt")
        self.trusted_domains = self.load_wordlist("resources/WORDLISTS/domains.txt")
        self.known_company = self.load_wordlist("resources/WORDLISTS/companies.txt")

        # extract sender info
        self.display_name, self.sender_email = self.extract_sender_info()
        self.sender_domain = self.extract_domain(self.sender_email)
    
    #FOR Testing without eml files
    @classmethod
    def from_sender_email(cls, sender_email: str):
        # Creates an EmailVerifier instance for testing without an Email object.
        obj = cls.__new__(cls) 

        obj.email = None
        obj.risk_score = 0
        obj.flags = {}

        obj.trusted_emails = obj.load_wordlist("resources/WORDLISTS/trusted_emails.txt")
        obj.trusted_domains = obj.load_wordlist("resources/WORDLISTS/domains.txt")
        obj.known_company = obj.load_wordlist("resources/WORDLISTS/companies.txt")

        obj.display_name = ""
        obj.sender_email = sender_email.lower()
        obj.sender_domain = obj.extract_domain(obj.sender_email)

        return obj

    def load_wordlist(self, filepath: str) -> set:
        with open(filepath, "r", encoding="utf-8") as file:
            return {
                line.strip().lower()
                for line in file
                if line.strip() and not line.startswith("#")
            }
        
    # separates sender display name and email address from From header
    def extract_sender_info(self):
        name, addr = parseaddr(self.email.sender)
        return name.lower(), addr.lower()

    def extract_domain(self, email_addr):
        if "@" not in email_addr:
            return ""
        return email_addr.split("@")[-1]

    #normalize domain to remove space and covert to lower case
    def normalize_domain(self, domain):
        return domain.lower().strip() if domain else ""
    
    #Checks if the email is in the trusted.txt
    def trusted_email_check(self):
        if self.sender_email in self.trusted_emails:
            self.flags["trusted_email"] = True
            self.risk_score -= 5
            return True
        return False

    #checks if sender domain is trusted
    def domain_whitelist_check(self):
        domain = self.sender_domain

        for trusted in self.trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                self.flags["whitelisted domain"] = True
                self.risk_score -= 2
                return

        self.flags["whitelisted domain"] = False
        
    def display_name_mismatch_check(self):
        for company in self.known_company:
            if company in self.display_name and company not in self.sender_domain:
                self.flags["display_name_mismatch"] = True
                self.risk_score += 3
                return

    #checks if sender uses sus words in their domain
    def domain_pattern_check(self):
        sus_words = [
            "secure", "verify", "login", "update",
            "account", "support", "billing", "real"
        ]

        for word in sus_words:
            if word in self.sender_domain:
                self.flags["suspicious_pattern"] = True
                self.risk_score += 2
                return
                    
    # computes distance between 2 strings. To measure similarity
    def edit_distance(self, a, b):
        dp = [[0] * (len(b)+1) for _ in range(len(a)+1)]

        for i in range(len(a)+1):
            dp[i][0] = i
        for j in range(len(b)+1):
            dp[0][j] = j

        for i in range(1, len(a)+1):
            for j in range(1, len(b)+1):
                cost = 0 if a[i-1] == b[j-1] else 1
                dp[i][j] = min(
                    dp[i-1][j] + 1,
                    dp[i][j-1] + 1,
                    dp[i-1][j-1] + cost
                )
        return dp[-1][-1]

    # compares the distance between sender and trusted domains.
    def lookalike_domain_check(self):
        for trusted in self.trusted_domains:
            dist = self.edit_distance(self.sender_domain, trusted)
            if 0 < dist <= 2:
                self.flags["lookalike_domain"] = True
                self.risk_score += 4
                return
                   
    #checks if domain is impersonating a domain e.g. suspisciouspaypal.com
    def brand_in_domain_check(self):
        for company in self.known_company:
            if company in self.sender_domain:
                for trusted in self.trusted_domains:
                    if company in trusted and self.sender_domain != trusted:
                        self.flags["brand_impersonation"] = True
                        self.risk_score += 4
                        return

    # runs all checks and give the final risk score
    def run_verification(self):
        self.sender_domain = self.normalize_domain(self.sender_domain)
        #skips other checks if email is trusted. Might want to add other checks to see if trusted email is actually trusted
        if self.trusted_email_check():
            return {
                "risk_score": self.risk_score,
                "flags": self.flags
            }

        self.domain_whitelist_check()
        self.display_name_mismatch_check()
        self.domain_pattern_check()
        self.lookalike_domain_check()
        self.brand_in_domain_check()

        return {
            "risk_score": self.risk_score,
            "flags": self.flags
        }

#test

# email = Email("Resources/DATASET/Project Proposal.eml")
verifier = EmailVerifier.from_sender_email("test@paypal-secure-login.com")

# print("Subject:", email.subject)
# print("Sender:", email.sender)
# print("Domain:", verifier.sender_domain)
# print("Display name:", verifier.display_name)


result = verifier.run_verification()
print(result)