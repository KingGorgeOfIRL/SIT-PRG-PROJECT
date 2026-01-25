from socket import create_connection
from requests import get

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

###### IDEA??
# each check give the URL a certain score, higher score, higher sus

class UrlCheck(Email):
    def __init__(self, email_path = None):
        super().__init__(email_path)

        self.urls.append("https://19.201.39.2/|+")
        self.urls.append("https://example.com")
        self.urls.append("https://google.com")
        self.urls.append("http://127.0.0.1:8080/test")
        
        self.url_score = {url: 0 for url in self.urls}
        self.connectivity:[bool] = self.__internet_check()

    def __internet_check(self):
        try:
            create_connection(("www.google.com", 80), timeout=3)
            return True
        except Exception as e:
            print(e)
            return False      

    # check if is https [10]
    def ssl_check(self):
        for url in self.urls:
            # get scheme
            scheme = url.split("://", 1)[0]
            
            if scheme == 'http':
                self.url_score[url] += 10
                print(self.url_score)
        return "DANGERRRRRRRRRRRRRRRRRRRRRR"   

    # check if url is just IP address [20]
    def ip_check(self):
        for original_url in self.urls:

            # remove scheme
            url = original_url.split("://", 1)[1]

            # remove path
            url = url.split("/", 1)[0]
            
            # remove port
            url = url.split(":", 1)[0]
            
            # splitting
            parts = url.split(".")
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                self.url_score[original_url] += 20

            print(self.url_score)
        return "DANGERRRRRRRRRRRRRRRRRRRRRR"

    # check if it specifies non default ports [20]
    def port_check(self):
        
        # list (maybe replace it and put in txt file)
        default_ports = [80, 443] # wanna add 8080 & 8000?

        for original_url in self.urls:
            # remove scheme
            url = original_url.split("://", 1)[1]

            # remove path
            url = url.split("/", 1)[0]

            # check for port
            if ":" in url:
                port = (url.split(":", 1)[1])
            
                if port not in default_ports:
                    self.url_score[original_url] += 20

        print(self.url_score)
        return

    # check if url is shorten [10]
    def urlShortener_check(self):
        # wmtips.com/technologies/url-shorteners/
        url_shorteners = ["bitly.com", "eepurl.com", "amzn.to", "t.co", "g.co", "tinyurl.com", "cutt.ly", "rebrandly.com", "linkfire.com", "fb.me", "t.ly",  "apple.co", "shorturl.com", "geniuslink.com", "short.io", "is.gd", "ow.ly", "lnkd.in", "bl.ink", "yandexclicker.ru", "tiny.cc", "t2m.io", "yourls.org", "sniply.com", "joturl.com"]

        for original_url in self.urls:

            # remove scheme
            url = original_url.split("://", 1)[1]

            # remove path
            url = url.split("/", 1)[0]
            
            # remove port
            domain = url.split(":", 1)[0]

            if domain in url_shorteners:
                self.url_score[original_url] += 10


    # check for suspicious url length [5~10]
    # Typical safe URLs: < 75–100 characters
    # Suspiciously long: > 200–250 characters
    # Extreme: > 500 characters (almost always automated/obfuscated)
    def length_check(self):
        for url in self.urls:
            url_length = len(url)
            
            if url_length > 500:
                self.url_score[url] += 10
                return
            
            # find length from sources!!!!!
            elif url_length > 250 or url_length < 30:
                self.url_score[url] += 5
                return

    # detech suspicious special char [20]
    def specialChar_check(self):

        # add more if needed
        suspicious_chars = set('%!$*()<>{}|\\^`"\'')

        for url in self.urls:
            if any(char in suspicious_chars for char in url):
                self.url_score[url] += 20
        print(self.url_score)
        return

    # VERY MAFAN, WILL HAVE TO DECIDE HOW I WANRT TO DO IT (DO I WANT TO USE KNOWN BRANDS? OR JUST USE ALGO TO TRY N DETECT???)
    def spelling_check(self):
        leet_map = {'A': ['a', '4', '@']}

        for original_url in self.urls:

            # remove scheme
            url = original_url.split("://", 1)[1]

            # remove path
            url = url.split("/", 1)[0]
            
            # remove port
            url = url.split(":", 1)[0]
    # VERY MAFAN, WILL HAVE TO DECIDE HOW I WANRT TO DO IT (DO I WANT TO USE KNOWN BRANDS? OR JUST USE ALGO TO TRY N DETECT???)

    # @ symbol detection [30]
    def at_symbol_check(self):
        for original_url in self.urls:

            # remove scheme
            url = original_url.split("://", 1)[1]

            # remove path
            url = url.split("/", 1)[0]
            
            # remove port
            url = url.split(":", 1)[0]

            if '@' in url:
                self.url_score[url] += 30

    # remember to use self.connectivity to check for internet connection first (Boolean value)
    # check for common redirection parameters [10]
    def offline_redirection_check(self):
        # https://hackmd.io/@ladieubong2004/SyGfnIWbbe
        # https://scnps.co/papers/ndss25_open_redirects.pdf (or can use this :0)
        common_redirection_parameters = ['redirect', 'redirect_to', 'url', 'link', 'goto', 'return', 'returnTo', 'destination', 'next', 'checkout', 'checkout_url', 'continue', 'return_path', 'return_url', 'forward', 'path', 'redir', 'redirect_uri', 'view', 'img_url', 'image_url', 'load_url']

        for url in self.urls:

            # check if theres paramters
            if '?' in url:
                parameter = url.split('?', 1)[1]

                if parameter in common_redirection_parameters:
                    self.url_score[url] += 10


    # remember to use self.connectivity to check for internet connection first (Boolean value)
    # if it redirects user [20]
    # def online_redirection_check(self):
    #     for url in self.urls:
    #         try:
    #             response = get(url, timeout = 10)
    #             print(response.url)
    #             print(response.history)
    #             if response.status_code == 301:
    #                 print('w')
    #         except:
    #             print("SITE DOeSN\'t EXIST")


    # remember to use self.connectivity to check for internet connection first (Boolean value)
    # how authoritative a site is [10/20]
    # more subdomain = less
    def domain_page_rank_check(self):

        # maybe can put this somewhere else
        API_KEY = 'swkk00k4ww4osgo4wc4wco0sogowcs0o40kg0wo0'
        page_rank_url = "https://openpagerank.com/api/v1.0/getPageRank"

        headers = {"API-OPR": API_KEY}

        for url in self.urls:
            
            domain = url.split("/")[0] + "//" + url.split("/")[2]
            domain = url
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
                            self.url_score[url] += 10
                        case _ if page_rank <= 6:
                            self.url_score[url] += 5

                # domain doesn't exist
                else:
                    self.url_score[url] += 20

            # website down / no internet
            else:
                return False


    # def domain_age_check(self):



u = UrlCheck("Resources/DATASET/URL Checker_3.eml")
u.online_redirection_check()