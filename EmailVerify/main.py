from os import listdir, remove, path, mkdir
from zipfile import ZipFile
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
import time

from email import policy
from email.parser import Parser, HeaderParser
from html.parser import HTMLParser
from io import StringIO
import base64

class EmailVerifier:
    def __init__(self, sender_email, sender_domain, display_name, reply_to_domain=None):
        self.sender_email = sender_email
        self.sender_domain = sender_domain
        #self.reply_to_domain = reply_to_domain (if we are doing)
        self.display_name = display_name.lower()

        self.risk_score = 0
        self.flags = {}

        self.trusted_domains = {
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "edu.sg",
            "gov.sg"
            "icloud.com",
        }

        self.known_company = {
            "singtel",
            "google",
            "microsoft",
            "apple",
            "amazon",
            "paypal"
        }

    #normalize domain to remove space and covert to lower case
    def normalize_domain(self, domain):
        if domain is None:
            return None
        return domain.strip().lower()

    #checks if sender domain is trusted
    def domain_whitelist_check(self):
        domain = self.sender_domain
        for trusted in self.trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                self.flags["whitelisted"] = True
                self.risk_score -= 2
                return

        self.flags["whitelisted"] = False
        
    # checks if there is mismatch between sender and reply
    def reply_to_mismatch_check(self):
        if not self.reply_to_domain:
            return

        if self.reply_to_domain != self.sender_domain:
            self.flags["reply_to_mismatch"] = True
            self.risk_score += 3

    # Checks if sender name and sender domain matches
    def display_name_mismatch_check(self):
        for company in self.known_company:
            if company in self.display_name and company not in self.sender_domain:
                self.flags["display_name_mismatch"] = True
                self.risk_score += 3
                return

    #checks if sender uses sus words in their domain
    def domain_pattern_check(self):
        sus_words = ["secure", "verify", "login", "update", "account", "support", "billing", "real"]

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

    # runs all checks and give the final risk score
    def run_verification(self):
        self.sender_domain = self.normalize_domain(self.sender_domain)
        # self.reply_to_domain = self.normalize_domain(self.reply_to_domain)

        self.domain_whitelist_check()
        #self.reply_to_mismatch_check()
        self.display_name_mismatch_check()
        self.domain_pattern_check()
        self.lookalike_domain_check()

        return {
            "risk_score": self.risk_score,
            "flags": self.flags
        }

#test
email = EmailVerifier(
    sender_email="support@paypa1.com",
    sender_domain="paypa1.com",
    display_name="PayPal Support"
)

result = email.run_verification()
print(result)