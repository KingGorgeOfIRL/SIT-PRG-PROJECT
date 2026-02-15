from socket import create_connection
from requests import get, post
import datetime
from vtapi3 import VirusTotalAPIUrls
from json import loads
from LangAnalysis.main import Email

class UrlCheck(Email):
    """
    UrlCheck extends the Email analysis class and focuses on
    identifying potentially malicious URLs found within emails.

    The class performs both offline and online checks depending
    on internet availability and records triggered indicators
    per URL for risk scoring.
    """

    def __init__(self, email_path = None):
        super().__init__(email_path)

        # ensure urls attribute exists even if none were found (prevent error)
        if not hasattr(self, "urls") or self.urls is None:
            self.urls = []
        
        # check internet availability for online-based analysis
        self.connectivity:[bool] = self.__internet_check()

        # pre-split each URL into logical components
        self.url_split:{str: {str: str}} = self.__url_dissection()

        # store which checks triggered per URL
        self.triggered_checks = {url: [] for url in self.urls}

    # add check
    def __apply_check(self, check_name, url):
        """
        Records a detection event for a URL.
        Ensures the same check is not duplicated.
        """
        if check_name not in self.triggered_checks[url]:
            self.triggered_checks[url].append(check_name)

        return True

    # check for internet connection
    def __internet_check(self):
        """
        Attempts a lightweight socket connection to verify
        whether online checks (redirection, ranking, VT) can run.
        """
        try:
            s = create_connection(("www.google.com", 80), timeout=3)
            s.close()
            return True
        except Exception as e:
            print(e)
            return False   
    
    # split url into: scheme, path, domain, & port
    def __url_dissection(self):
        """
        Breaks each URL into individual components so that
        specific heuristics (port usage, IP-based URLs, etc.)
        can be applied reliably.
        """
        url_split_dict = {url: {} for url in self.urls}

        for url in self.urls:
            scheme = None
            domain = None
            port = None
            path = None

            # scheme (http / https)
            if "://" in url:
                scheme, remainder = url.split("://", 1)
            else:
                remainder = url

            # path (everything after first slash)
            if "/" in remainder:
                host, path = remainder.split("/", 1)
            else:
                host = remainder
                path = None

            # domain and port
            if ":" in host:
                domain, port = host.split(":", 1)
            else:
                domain = host
                port = None

            url_split_dict[url]["scheme"] = scheme
            url_split_dict[url]["domain"] = domain
            url_split_dict[url]["port"] = port
            url_split_dict[url]["path"] = path

        return url_split_dict
      
    # extract wordlist
    def extract_wordlist(self, filename=None):
        """
        Loads predefined wordlists used for heuristic detection
        (ports, shorteners, special characters, etc.).
        """
        with open(f'Resources/WORDLISTS/url_check/{filename}', "r", encoding="utf-8") as f:
            wordlist = f.read().split()

        return wordlist

    # check if is https
    def ssl_check(self):
        """
        Flags URLs using HTTP instead of HTTPS, lacking of TLS
        """
        for url in self.urls:
            
            # get scheme
            scheme = self.url_split[url]['scheme']

            if scheme == 'http':
                self.__apply_check("ssl_check", url)

        return True   

    # check if url is just IP address
    def ip_check(self):
        """
        Detects URLs that directly use an IP address instead of a domain name
        """
        for url in self.urls:
            domain = self.url_split[url]['domain']
            parts = domain.split(".")

            # IPv4 format validation
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                self.__apply_check("ip_check", url)

        return True

    # check if it specifies non default ports
    def port_check(self):
        """
        Flags URLs using uncommon ports, which may indicate
        command-and-control or bypass attempts
        """
        wordlist = self.extract_wordlist('default_ports.txt')

        for url in self.urls:
            port = self.url_split[url]['port']

            if port is not None and str(port) not in wordlist:
                self.__apply_check("port_check", url)

        return True

    # check if url is shorten
    def urlShortener_check(self):
        """
        Identifies known URL shortening services, which are
        commonly abused to obscure final destinations.
        """
        # wmtips.com/technologies/url-shorteners/
        wordlist = self.extract_wordlist('url_shorteners.txt')

        for url in self.urls:
            domain = self.url_split[url]['domain']

            if domain in wordlist:
                self.__apply_check("urlShortener_check", url)

        return True

    # check for suspicious url length
    # Checking 30 < length > 250
    def length_check(self):
        """
        Flags URLs that are unusually short or excessively long,
        both of which can indicate obfuscation or redirection abuse.
        """
        for url in self.urls:
            url_length = len(url)
            
            if url_length > 250 or url_length < 30:
                self.__apply_check("length_check", url)

        return True

    # excessive subdomain
    def subdomain_check(self):
        """
        Detects excessive subdomain depth, often used to mimic
        legitimate brands or evade filtering.
        """
        for url in self.urls:
            domain = self.url_split[url]['domain']
            
            if domain.count('.') > 3:
                self.__apply_check("subdomain_check", url)

        return True

    # detect suspicious special char
    def specialChar_check(self):
        """
        Flags URLs containing suspicious special characters
        commonly used in obfuscation or injection attempts.
        """
        wordlist = self.extract_wordlist('suspicious_chars.txt')

        for url in self.urls:
            if any(char in wordlist for char in url):
                self.__apply_check("specialChar_check", url)

        return True

    # @ symbol detection
    def at_symbol_check(self):
        """
        Detects '@' symbol usage, which can be used to hide
        the true destination of a URL.
        """
        for url in self.urls:
            domain = self.url_split[url]['domain']

            if '@' in domain:
                self.__apply_check("at_symbol_check", url)

        return True

    # punycode check
    def punycode_check(self):
        """
        Detects IDN homograph attacks using punycode
        (e.g., xn-- prefixed domains).
        """
        for url in self.urls:
            domain = self.url_split[url]['domain']

            if domain.startswith('xn--'):
                self.__apply_check("punycode_check", url)

        return True

    # check for common redirection parameters
    def offline_redirection_check(self):
        """
        Performs static analysis of URL parameters to detect
        potential open redirection without making requests.
        """
        # only run when no connectivity
        if self.connectivity == True:
            return False

        # https://hackmd.io/@ladieubong2004/SyGfnIWbbe
        # https://scnps.co/papers/ndss25_open_redirects.pdf (or can use this :0)
        wordlist = self.extract_wordlist('common_redirection_parameters.txt')

        # look for common redirection parameters in path
        for url in self.urls:
            if '?' in url:
                query = url.split('?', 1)[1]
                params = [p.split('=')[0] for p in query.split('&')]

                if any(p in wordlist for p in params):
                    self.__apply_check("offline_redirection_check", url)

        return True

    # if it redirects user
    def online_redirection_check(self):
        """
        Actively follows HTTP responses to determine whether
        the URL performs a redirection.
        """
        if self.connectivity == False:
            return False

        for url in self.urls:
            try:
                response = get(url, timeout = 10)

                # redirection occurred 
                if len(response.history) != 0:
                    self.__apply_check("online_redirection_check", url)

            # website doesn't exist
            except:
                # handled in domain_page_rank_check
                continue
        
        return True

    # how authoritative a site is
    # more subdomain = less
    def domain_page_rank_check(self):
        """
        Uses Open PageRank to estimate domain authority.
        Low-authority or unreachable domains are considered riskier.
        """
        if self.connectivity == False:
            return False

        API_KEY = 'swkk00k4ww4osgo4wc4wco0sogowcs0o40kg0wo0'
        page_rank_url = "https://openpagerank.com/api/v1.0/getPageRank"
        headers = {"API-OPR": API_KEY}

        for url in self.urls:
            # use domain instead of entire url
            domain = self.url_split[url]['domain']
            params = {"domains[]": domain}

            response = get(page_rank_url, headers=headers, params=params)
            json_response = response.json()

            # if url response
            if response.status_code == 200:
                # mainly looking for 3 things 
                # 1. status_code (if domain is reachable) 
                # 2. page_rank_decimal (higher num = more authoritative [1-10 with dp]) 
                    # Low PageRank (0–3) → either new, niche, or few backlinks. 
                    # Medium (4–6) → some authority; site is linked but not globally prominent. 
                    # High (7–10) → very authoritative, widely linked globally.

                if json_response['response'][0]['status_code'] == 200:
                    page_rank = json_response['response'][0]['page_rank_decimal']
                    match page_rank:
                        # low page rank
                        case _ if page_rank <= 3:
                            self.__apply_check("domain_page_rank_check", url)
                        # medium page rank
                        case _ if page_rank <= 6:
                            self.__apply_check("domain_page_rank_check_medium", url)
                # domain does not exist
                else:
                    self.__apply_check("domain_page_rank_check", url)

            # website down or connectivity issue
            else:
                return False

        return True

    # checking domain age
    def domain_age_check(self):
        """
        Determines how recently a domain was registered.
        Newly registered domains are frequently used in phishing.
        """
        for url in self.urls:
            subdomain = None
            domain = self.url_split[url]['domain']
            split_domain = domain.split('.')

            # ensure ip address are not split
            if len(split_domain) == 4:
                root_domain = domain
            else:
                # get root domain
                root_domain = domain.split(".")[-2] + '.' + domain.split(".")[-1]
                # get subdomain (if applicable)
                if len(split_domain) != 2:
                    subdomain = domain

            try:
                # try root domain first
                rdap_url = f"https://rdap.org/domain/{root_domain}"
                rdap_output = get(rdap_url, timeout = (2, 3))

                # if root domain does not work, try subdomain
                if rdap_output.status_code != 200 and subdomain != None:
                    rdap_url = f"https://rdap.org/domain/{subdomain}"
                    rdap_output = get(rdap_url, timeout = (2, 3))

                # get domain data
                data = rdap_output.json()
                
                registration_date = next(
                    e["eventDate"] for e in data["events"]
                    if e["eventAction"] == "registration"
                )

                # determine domain age
                registered_at = datetime.datetime.fromisoformat(
                    registration_date.replace("Z", "+00:00")
                )
                now = datetime.datetime.now(datetime.timezone.utc)
                age = now - registered_at

                # https://dnsrf.org/blog/phishing-attacks--newly-registered-domains-still-a-prominent-threat
                if age.days <= 4:
                    self.__apply_check("domain_age_check", url)

            # website does not exist
            except Exception as e:
                print(f"RDAP failed for {domain}: {e}")
                continue
        
        return True

    # check with virus total [100%]
    def virus_total(self):
        """
        Submits URLs to VirusTotal and evaluates consensus
        engine verdicts for malicious or suspicious behavior.
        """
        if self.connectivity == False:
            return False

        API_KEY = 'aab69934a49f25e21cc381f20ad2be87133207bfd0bcfe41b6f2728515307c75'
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        for url in self.urls:
            try:   
                # get analysis id
                response = post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url},)
                analysis_id = response.json()["data"]["id"]

                # get report using analysis id
                report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                report_response = get(report_url, headers=headers)
                report_data = report_response.json()
                report_stats = report_data["data"]['attributes']['stats']
                
                # get highest rated field
                highest_score = max(report_stats, key=report_stats.get)
                
                match highest_score:
                    case 'malicious':
                        self.__apply_risk_score("virus_total", url, 50)
                    case 'suspicious':
                        self.__apply_risk_score("virus_total", url, 50)

            except Exception as e:
                print(e)
                continue

        return True

    def run_all_checks(self):
        """
        Executes all URL analysis checks and returns
        connectivity status and triggered indicators.
        """
        max_score = 0

        self.ssl_check()
        self.ip_check()
        self.port_check()
        self.urlShortener_check()
        self.length_check()
        self.subdomain_check()
        self.specialChar_check()
        self.at_symbol_check()
        self.punycode_check()

        # double confirm the connectivity to ensure no delay
        if self.connectivity == False:
            self.offline_redirection_check()
        else:
            self.offline_redirection_check()
            self.online_redirection_check()
            self.domain_page_rank_check()
            self.domain_age_check()
            #self.virus_total()

        return self.connectivity, self.triggered_checks


# calculate risk score (score/total possible score)
def risk_score_calculate(connectivity:bool, triggered_checks:dict):
    """
    Aggregates triggered URL indicators into a weighted
    risk score and ranks URLs by severity.
    """
    critical_checks = {"domain_age_check", "punycode_check", "domain_page_rank_check"}
    high_checks = {"online_redirection_check", "offline_redirection_check", "at_symbol_check", "specialChar_check", "urlShortener_check", "ip_check", "domain_page_rank_check_medium"}

    final_url_score:{str: int} = {}

    for url, checks in triggered_checks.items():
        score = 0.0
        counted = {"critical":0, "high":0, "other":0}

        # first check for each category will have higher weightage
        # subsequent checks in same category will have lower weightage
        for check in checks:
            if check in critical_checks:
                base = 70 if counted["critical"] == 0 else 5
                counted["critical"] += 1
            elif check in high_checks:
                base = 10 if counted["high"] == 0 else 2
                counted["high"] += 1
            else:
                base = 5 if counted["other"] == 0 else 1
                counted["other"] += 1

            score += base

        final_url_score[url] = min(score, 100.0)

    ranked_url = sorted(final_url_score.items(), key=lambda x: x[1], reverse=True)

    return ranked_url, triggered_checks