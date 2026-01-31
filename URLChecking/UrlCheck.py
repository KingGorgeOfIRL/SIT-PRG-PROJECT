from socket import create_connection
from requests import get, post
from datetime import datetime, timezone
from vtapi3 import VirusTotalAPIUrls
from json import loads

from os import listdir, remove, path
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
        self.urls = extract[3]
        self.subject:str = headers['Subject'] 
        self.sender:str = headers['From'] 
        self.headers:dict = headers 
        
    #extracts all body text free of HTML tags
    def __extract_body(self):
        with open(self.email_path,'r') as file:
            raw = Parser(policy=policy.default).parse(file)
        attachment_header = []
        urls = []
        plain_text:str = None
        for part in raw.walk():
            if part.is_attachment():
                # print("attachment found",part.get('Content-Disposition'))
                if "base64" in part.get("Content-Transfer-Encoding"):
                    attachment_header.append(self.__bs64_save_attachments(part.get_payload(),part.get('Content-Disposition')))
                else:
                    print("cannot save file. not the right encoding")
            elif 'text/plain' in part.get('Content-Type'):
                plain_text = str(part.get_payload(decode=True))
            elif 'text/html' in part.get('Content-Type'):
                plain_text = strip_tags(str(part.get_payload(decode=True).decode("utf-8")))
                html_content = part.get_payload(decode=True).decode("utf-8", errors="ignore")

                ################################## pick which method is better
                # extract urls - method 1
                # if "href=" in html_content.lower():
                #     import re
                #     urls = re.findall(r'href=["\'](.*?)["\']', html_content)

                #     print(urls)

                # extract urls - method 2
                if "href=" in html_content.lower():
                    urls = []

                    start = 0
                    while True:
                        href_pos = html_content.find('href="', start)
                        if href_pos == -1:
                            break

                        href_pos += len('href="')
                        end_pos = html_content.find('"', href_pos)

                        urls.append(html_content[href_pos:end_pos])
                        start = end_pos

                    #print(urls)
                        
        return plain_text,attachment_header,raw,urls
    
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

        if path.exists(output_path) == False:
            mkdir(output_path)

        with open(f"{output_path}/{name}", "wb") as f:
            f.write(file_bytes)

        return meta_data

    def __repr__(self):
        return f"Email<Subject:{self.subject},Sender:{self.sender}>"





#### IDEA:
# be able to add/remove stuff into WORDLISTS


class UrlCheck(Email):
    def __init__(self, email_path = None):
        super().__init__(email_path)

        # testing purpose
        self.urls.append("https://19.201.39.2/|+")
        self.urls.append("https://login.verify.bank.transfer.example.com")
        self.urls.append("https://google.com")
        self.urls.append("http://127.0.0.1:8080/test")
        self.urls.append("http://tinyurl.com/time0ut/main.html")
        self.urls.append("http://youtube.com@google.com")
        self.urls.append("https://malicious.com:9901/bank?redir=skem.com")
        
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
        with open(f'URLChecking/temp_wordlist/{filename}', "r", encoding="utf-8") as f:
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
