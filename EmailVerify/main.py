from os import listdir, remove, path
from zipfile import ZipFile
from email.utils import parsedate_to_datetime, parseaddr
from LangAnalysis import Email

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