from os import listdir, remove, path
from typing import Set, Dict, Tuple, Any
from zipfile import ZipFile
from email.utils import parsedate_to_datetime, parseaddr
from DocChecking.DocCheck import extract_wordlist
from LangAnalysis.email_extract import Email
 
class EmailVerifier:
    #centralised risk weights
    #easier for me to compute max risk score.
    RISK_WEIGHTS = {
        "unknown_sender": 1,
        "display_name_mismatch": 3,
        "suspicious_pattern": 2,
        "brand_impersonation": 4,
        "suspicious_domain_structure": 1,
        "sender_username_suspicious": 2,
        "local_part_suspicious": 2,
    }

    def __init__(self, email):
        self.email: Email = email
        self.risk_score: int = 0
        self.flags: Dict[str,bool] = {}
        self.max_risk_score: int = sum(self.RISK_WEIGHTS.values())
        #loads trusted emails, domains and known companies from files
        # self.trusted_emails: Set[str] = self.load_wordlist("resources/WORDLISTS/email_verify/trusted_emails.txt")
        # self.trusted_domains: Set[str] = self.load_wordlist("resources/WORDLISTS/email_verify/domains.txt")
        # self.known_company: Set[str] = self.load_wordlist("resources/WORDLISTS/email_verify/companies.txt")
        # self.known_suswords: Set[str] = self.load_wordlist("Resources/WORDLISTS/email_verify/suspisciouswords.txt")
        self.trusted_emails: Set[str] = set( word.lower() for word in extract_wordlist("email_verify", "trusted_emails.txt"))
        self.trusted_domains: Set[str] = set( word.lower() for word in extract_wordlist("email_verify", "domains.txt"))
        self.known_company: Set[str] = set( word.lower() for word in extract_wordlist("email_verify", "companies.txt"))
        self.known_suswords: Set[str] = set(word.lower() for word in extract_wordlist("email_verify", "suspisciouswords.txt"))
        
        #extract sender info
        
        self.display_name: str
        self.sender_email: str
        self.sender_domain: str
        self.display_name, self.sender_email = self.extract_sender_info()
        self.sender_domain = self.extract_domain(self.sender_email)

    
    # def load_wordlist(self, filepath: str) -> set:
    #     with open(filepath, "r", encoding="utf-8") as file:
    #         return {
    #             line.strip().lower()
    #             for line in file
    #             if line.strip() and not line.startswith("#")
    #         }
        
    #separates sender display name and email address from From header
    def extract_sender_info(self) -> Tuple[str, str]:
        name, addr = parseaddr(self.email.sender)
        return name.lower(), addr.lower()


    def extract_domain(self, email_addr: str) -> str:
        if "@" not in email_addr:
            return ""
        return email_addr.split("@")[-1]

    #normalize domain to remove space and covert to lower case
    def normalize_domain(self, domain: str) -> str:
        return domain.lower().strip() if domain else ""
    
    #checks if the email is in the trusted.txt
    def trusted_email_check(self) -> bool:
        if self.sender_email in self.trusted_emails:
            self.flags["trusted_email"] = True
            return True
        else:
            self.flags["unknown_sender"] = True
            self.risk_score += self.RISK_WEIGHTS["unknown_sender"]
            return False

    #checks if sender domain is trusted
    def domain_whitelist_check(self) -> None:
        domain: str = self.sender_domain

        self.flags["whitelisted_domain"] = False
        for trusted in self.trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                self.flags["whitelisted_domain"] = True
                self.risk_score -= 3
                break
        
    def display_name_mismatch_check(self) -> None:
        for company in self.known_company:
            if company in self.display_name and company not in self.sender_domain:
                self.flags["display_name_mismatch"] = True
                self.risk_score += self.RISK_WEIGHTS["display_name_mismatch"]
                return

    #checks if sender uses suspicious words in the local part of the email (before the @)     
    def sender_username_check(self) -> None:
        if not self.sender_email or "@" not in self.sender_email:
            return

        local_part: str = self.sender_email.split("@")[0]

        for word in self.known_suswords:
            if word in local_part:
                self.flags["sender_username_suspicious"] = True
                self.risk_score += self.RISK_WEIGHTS["sender_username_suspicious"]
                return

        # brand name in local part but not in domain
        for company in self.known_company:
            if company in local_part and company not in self.sender_domain:
                self.flags["local_part_brand_impersonation"] = True
                self.risk_score += self.RISK_WEIGHTS["local_part_suspicious"]
                return
                
    #checks if sender uses suspicious words in their domain
    def domain_pattern_check(self) -> None:
        for word in self.known_suswords:
            if word in self.sender_domain:
                self.flags["suspicious_pattern"] = True
                self.risk_score += self.RISK_WEIGHTS["suspicious_pattern"]
                return

            
    #checks subdomain depth
    def suspicious_domain_structure_check(self) -> None:
        if not self.sender_domain:
            return

        dot_count: int = self.sender_domain.count(".")

        # mail.company.com -> 2 dots (OK)
        # login.secure.update.company.com -> 4+ dots (suspicious)
        if dot_count >= 4:
            self.flags["suspicious_domain_structure"] = True
            self.risk_score += self.RISK_WEIGHTS["suspicious_domain_structure"]

    # computes distance between 2 strings. To measure similarity
    def edit_distance(self, a: str, b: str) -> int:
        dp: list[list[int]] = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

        for i in range(len(a) + 1):
            dp[i][0] = i
        for j in range(len(b) + 1):
            dp[0][j] = j

        for i in range(1, len(a) + 1):
            for j in range(1, len(b) + 1):
                cost: int = 0 if a[i - 1] == b[j - 1] else 1
                dp[i][j] = min(
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + cost
                )

        return dp[-1][-1]

    # compares the distance between sender and trusted domains.
    def lookalike_domain_check(self) -> None:
        for trusted in self.trusted_domains:
            dist: int = self.edit_distance(self.sender_domain, trusted)
            if 0 < dist <= 2:
                self.flags["lookalike_domain"] = True
                self.risk_score += 20
                return

    #checks if domain is impersonating a domain e.g. suspisciouspaypal.com
    def brand_in_domain_check(self):
        for company in self.known_company:
            if company in self.sender_domain:
                for trusted in self.trusted_domains:
                    if company in trusted and self.sender_domain != trusted:
                        self.flags["brand_impersonation"] = True
                        self.risk_score += self.RISK_WEIGHTS["brand_impersonation"]
                        return
                    
    #increases risk slightly if local part is suspiscious and domain is not whitelisted
    def username_domain_mismatch(self) -> None:
        if (
            self.flags.get("sender_username_suspicious")
            and not self.flags.get("whitelisted_domain")
        ):
            self.flags["username_domain_mismatch"] = True
            self.risk_score += 2


    def get_risk_percentage(self) -> float:
        if self.risk_score <= 0:
            return 0.0

        percentage: float = (self.risk_score / self.max_risk_score) * 100
        return min(percentage, 100.0)
    

    def _final_result(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_percentage": round(self.get_risk_percentage(), 2),
            "flags": self.flags
        }
    
    # runs all checks and give the final risk score
    def run_verification(self) -> Dict[str, Any]:
        self.sender_domain = self.normalize_domain(self.sender_domain)

        # skip other checks if email is trusted
        if self.trusted_email_check():
            return self._final_result()

        self.domain_whitelist_check()
        self.display_name_mismatch_check()
        self.suspicious_domain_structure_check()
        self.sender_username_check()
        self.domain_pattern_check()
        self.lookalike_domain_check()
        self.brand_in_domain_check()
        self.username_domain_mismatch()

        return self._final_result()

# #test
# email = Email("Resources/DATASET/lennontest.eml")
# verifier = EmailVerifier(email)