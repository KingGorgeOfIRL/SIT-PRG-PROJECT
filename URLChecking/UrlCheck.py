from socket import create_connection
from requests import get, post
from datetime import datetime, timezone
from vtapi3 import VirusTotalAPIUrls
from json import loads
from LangAnalysis import Email

class UrlCheck(Email):
    def __init__(self, email_path = None):
        super().__init__(email_path)

        # testing purpose
        # self.urls.append("https://19.201.39.2/|+")
        # self.urls.append("https://login.verify.bank.transfer.example.com")
        # self.urls.append("https://google.com")
        # self.urls.append("http://127.0.0.1:8080/test")
        # self.urls.append("http://tinyurl.com/time0ut/main.html")
        # self.urls.append("http://youtube.com@google.com")
        # self.urls.append("https://malicious.com:9901/bank?redir=skem.com")
        
        self.url_score = {url: 0 for url in self.urls}
        self.connectivity:[bool] = self.__internet_check()
        self.url_split:{str: {str: str}} = self.__url_dissection()

    def __internet_check(self):
        try:
            create_connection(("www.google.com", 80), timeout=3)
            return True
        except Exception as e:
            print(e)
            return False   

    def __url_dissection(self):
        
        url_split_dict = {url: {} for url in self.urls}

        for url in self.urls:

            scheme = None
            domain = None
            port = None
            path = None

            # scheme
            if "://" in url:
                scheme, remainder = url.split("://", 1)
            else:
                remainder = url

            # path
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
    # REMEMBER TO CHANGE FILE PATH
    def extract_wordlist(self, filename=None):
        with open(f'Resources/WORDLISTS/url_check/{filename}', "r", encoding="utf-8") as f:
            wordlist = f.read().split()

        return wordlist

    # check if is https [10]
    def ssl_check(self):
        for url in self.urls:
            
            # get scheme
            scheme = self.url_split[url]['scheme']
            
            if scheme == 'http':
                self.url_score[url] += 10

        return True   

    # check if url is just IP address [20]
    def ip_check(self):
        for url in self.urls:

            # domain
            domain = self.url_split[url]['domain']
            
            # splitting domain
            parts = domain.split(".")

            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                self.url_score[url] += 20

        return True

    # check if it specifies non default ports [20]
    def port_check(self):
        
        # list (maybe replace it and put in txt file)
        wordlist = self.extract_wordlist('default_ports.txt')

        for url in self.urls:

            port = self.url_split[url]['port']

            if port not in wordlist and port != None:
                self.url_score[url] += 20

        return True

    # check if url is shorten [10]
    def urlShortener_check(self):
        # wmtips.com/technologies/url-shorteners/ ################
        wordlist = self.extract_wordlist('url_shorteners.txt')

        for url in self.urls:

            domain = self.url_split[url]['domain']

            if domain in wordlist:
                self.url_score[url] += 10

        return True


    # check for suspicious url length [5~10]
    # Typical safe URLs: < 75–100 characters
    # Suspiciously long: > 200–250 characters
    # Extreme: > 500 characters (almost always automated/obfuscated)
    def length_check(self):
        for url in self.urls:
            url_length = len(url)
            
            if url_length > 500:
                self.url_score[url] += 10
            
            # find length from sources!!!!! #############################
            elif url_length > 250 or url_length < 30:
                self.url_score[url] += 5

        return True

    # excessive subdomain [20]
    def subdomain_check(self):
        for url in self.urls:

            domain = self.url_split[url]['domain']
            
            if domain.count('.') > 3:
                self.url_score[url] += 20

        return True

    # detect suspicious special char [20]
    def specialChar_check(self):

        # add more if needed
        wordlist = self.extract_wordlist('suspicious_chars.txt')

        for url in self.urls:
            if any(char in wordlist for char in url):
                self.url_score[url] += 20

        return True

    # @ symbol detection [30]
    def at_symbol_check(self):
        for url in self.urls:

            domain = self.url_split[url]['domain']

            if '@' in domain:
                self.url_score[url] += 30

        return True

    # punycode check [40]
    def punycode_check(self):
        for url in self.urls:

            domain = self.url_split[url]['domain']

            if domain.startswith('xn--'):
                self.url_score[url] += 40

        return True

    # check for common redirection parameters [10]
    def offline_redirection_check(self):

        # only run when no connectivity
        if self.connectivity == True:
            return False

        # https://hackmd.io/@ladieubong2004/SyGfnIWbbe
        # https://scnps.co/papers/ndss25_open_redirects.pdf (or can use this :0)
        wordlist = self.extract_wordlist('common_redirection_parameters.txt')

        for url in self.urls:

            # check if theres paramters
            if '?' in url:
                query = url.split('?', 1)[1]
                params = query.split('=', 1)[0]
                print(params)

                if params in wordlist:
                    self.url_score[url] += 10

        return True


    # if it redirects user [20]
    def online_redirection_check(self):
        
        if self.connectivity == False:
            return False

        for url in self.urls:
            try:
                response = get(url, timeout = 10)

                # redirection occurred 
                if len(response.history) != 0:
                    self.url_score[url] += 20

            # website doesn't exist
            except:
                # is handled in domain_page_rank_check
                continue
        
        return True


    # how authoritative a site is [10~20]
    # more subdomain = less
    def domain_page_rank_check(self):

        if self.connectivity == False:
            return False

        # maybe can put this somewhere else ###################################
        API_KEY = 'swkk00k4ww4osgo4wc4wco0sogowcs0o40kg0wo0'
        page_rank_url = "https://openpagerank.com/api/v1.0/getPageRank"

        headers = {"API-OPR": API_KEY}

        for url in self.urls:
            
            # use domain instead of entire url
            domain = self.url_split[url]['domain']
            params = {"domains[]": domain}

            response = get(page_rank_url, headers=headers, params=params)
            json_response = response.json()

            # if can connect to url
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
                        case _ if page_rank <= 3:
                            self.url_score[url] += 20
                        case _ if page_rank <= 6:
                            self.url_score[url] += 10

                # domain doesn't exist
                else:
                    self.url_score[url] += 20

            # website down / no internet
            else:
                return False
        
        return True

    # checking domain age [20]
    def domain_age_check(self):
        for url in self.urls:
            subdomain = None
            placeholder = ''

            domain = self.url_split[url]['domain']
            split_domain = domain.split('.')

            # ensure ip address are not split
            if len(split_domain) == 4:
                root_domain = domain

            # get its root domain
            else:
                root_domain = domain.split(".")[-2] + '.' + domain.split(".")[-1]

                # get subdomain (if applicable)
                if len(split_domain) != 2:
                    subdomain = domain

            try:
                # try root domain
                rdap_url = f"https://rdap.org/domain/{root_domain}"
                rdap_output = get(rdap_url, timeout = 10)

                # if root domain does not work & subdomain exist
                if rdap_output.status_code != 200 and subdomain != None:
                    rdap_url = f"https://rdap.org/domain/{subdomain}"
                    rdap_output = get(rdap_url, timeout = 10)


                data = rdap_output.json()
                
                from datetime import datetime, timezone
                registration_date = next(
                    e["eventDate"] for e in data["events"]
                    if e["eventAction"] == "registration"
                )

                # parse ISO timestamp
                registered_at = datetime.fromisoformat(
                    registration_date.replace("Z", "+00:00")
                )

                # calculate age
                now = datetime.now(timezone.utc)
                age = now - registered_at

                # https://dnsrf.org/blog/phishing-attacks--newly-registered-domains-still-a-prominent-threat
                if age.days <= 4:
                    self.url_score[url] += 20

            # website doesn't exist
            except Exception as e:
                print(f"RDAP failed for {domain}: {e}")
        
        return True

    # pip install vtapi3
    # check with virus total [50]
    def virus_total(self):
        if self.connectivity == False:
            return False

        API_KEY = '0f91624513c562fc371b980638f0bf815e54fa4e52e8fb763c29113d0d02947a'
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        for url in self.urls:
            try:
                # get analysis id
                response = post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                )

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
                        self.url_score[url] += 50
                    
                    case 'suspicious':
                        self.url_score[url] += 50

            except Exception as e:
                print(e)

        return True


    def run_all_checks(self):
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
            self.online_redirection_check()
            self.domain_page_rank_check()
            self.domain_age_check()
            self.virus_total()

        return self.url_score, self.connectivity


# calculate risk score (score/total possible score)
def risk_score_calculate(url_risk_scores:dict, connectivity:bool):

    final_url_score = {url: 0 for url in url_risk_scores}

    if connectivity == True:
        max_score = 280
    else:
        max_score = 240

    for url, score in url_risk_scores.items():

        percentage = score/max_score * 100
        final_url_score[url] = round(percentage, 2)

    print(final_url_score)
    return final_url_score

u = UrlCheck("Resources/DATASET/URL Checker_3.eml")
url_scores, internet_connection = u.run_all_checks()
risk_score_calculate(url_scores, internet_connection)
