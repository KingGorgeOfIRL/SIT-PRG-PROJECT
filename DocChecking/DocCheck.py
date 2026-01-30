#from .main import Email  
from magic import *
from size import *
from zipfile import ZipFile
from time import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

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








class DocChecking(Email):
    def __init__(self, email_path = None):
        super().__init__(email_path)

        self.document_path:str = 'Resources/TEMP_FILES'
        self.files:list[str] = self.__get_files()
        self.extensions: dict[str, str] = self.__extension_extraction()
        self.file_size:int = (int(self.attachment_header[0]['size=']) / 1024) # convert to bytes
        self.metadata_date:dict = self.__date_extraction()
        self.file_score = {filename: 0 for filename in self.files}

    # return all files in TEMP_FILES
    def __get_files(self):
        if not path.exists(self.document_path):
            # no files
            return []
        else:
            # returns list of file names
            return [name for name in listdir(self.document_path) if path.isfile(path.join(self.document_path, name))]

    # extract & check for multiple extension as well [20]
    def __extension_extraction(self):
        extensions = {}
        risk_score = 0

        for file_name in self.files:
            file_split = file_name.split('.')

            if len(file_split) > 2:
                self.file_score[file_name] += 20

            extensions[file_name] = file_split[-1]

        return extensions
    
    # depending on the email class dk if it will have multiple
    def __date_extraction(self):
        metadata_dates = {filename: 0 for filename in self.files}

        for file_entry in self.attachment_header:
            filename = file_entry['filename=']

            creation_date_epoch = self.to_epoch_time(
                file_entry['creation-date=']
            )

            modified_date_epoch = self.to_epoch_time(
                file_entry['modification-date=']
            )

            metadata_dates[filename] = {
                "creation": creation_date_epoch,
                "modified": modified_date_epoch
            }

        return metadata_dates

    # extract wordlist
    # REMEMBER TO CHANGE FILE PATH
    def extract_wordlist(self, filename=None):
        with open(f'DocChecking/temp_wordlist/{filename}', "r", encoding="utf-8") as f:
            wordlist = f.read().split()

        return wordlist

    # convert date string to epoch (metadata check)
    def to_epoch_time(self, date: str):
        dt = parsedate_to_datetime(date)

        # if timezone is missing, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)

        return int(dt_utc.timestamp())

    # blocks executables [100%]
    def block_high_risk_files(self):

        wordlist = self.extract_wordlist('high_risk_extensions.txt')
        
        for files in self.extensions:
            # high risk extension detected
            if self.extensions[files] in wordlist:
                self.file_score[files] += 1000000 # change to max score

        return True

    # check metadata dates [30]
    def metadata_check(self):

        for file_name in self.metadata_date:

            epoch_time = int(time())

            if self.metadata_date[file_name]['creation'] == self.metadata_date[file_name]['modified']:
                self.file_score[files] += 30

            elif self.metadata_date[file_name]['creation'] >= epoch_time or self.metadata_date[file_name]['modified'] >= epoch_time:
                self.file_score[files] += 30

        return False

    #########################################################################################################
    #########################################################################################################
    #########################################################################################################
    # checks first few bytes to confirm extension [20]
    def magic_number_check(self):
        for files in self.extensions:
            with open(f'{self.document_path}/{files}.{self.extensions[files]}', 'rb') as fb:
                raw = fb.read()

            ################################################### ADD MORE EXTENSION!!!!!!!!!!!!!!!!!!
            match (self.extensions[files]):
                case 'docx' | 'xlsx' | 'pptx':
                    if raw.startswith(MS_OFFICE_MAGIC):
                        return 20
                    # can probably add more logic here, c how i wanna settle it
                    return 0
                
                # file extension not suppoerted to check
                case _:
                    print('end')

    #########################################################################################################
    #########################################################################################################
    #########################################################################################################
    # check if file size is suspicious [10]
    def size_check(self): 
        for files in self.extensions:
            print(self.extensions[files])
            match self.extensions[files]:
            ############################## filter out size.py and add in the cases 
                case 'docx':
                    if self.file_size <= DOCX_SIZE[0] or self.file_size >= DOCX_SIZE[1]:
                        return 0
                    return 1

                # file extension not suppoerted to check
                case _:
                    print('end')

    # checking for macro [10]
    def macro_extension_check(self):

        wordlist = self.extract_wordlist('macro_extensions.txt')
        
        for file_name in self.extensions:
            if self.extensions[file_name] in wordlist:
                self.file_score[file_name] += 10

                # check if macro exist in file
                macro_exist = self.macro_check(file_name)

                if macro_exist:
                    self.file_score[file_name] += 50

        return True

    # check if macro file contains macro [50]
    def macro_check(self, file_name):

        # will usually contain vbaProject.bin
        with ZipFile(f"{self.document_path}/{file_name}") as z:
            if any("vbaProject.bin" in name for name in z.namelist()) == True:
                return True

        return False

   
    # always clear files after check
    def exit_check(self):
        for file_name in self.files:
            remove(f"{self.document_path}/{file_name}")

    def run_all_checks(self):
        self.block_high_risk_files()
        self.metadata_check()
        self.magic_number_check()
        self.size_check()
        self.macro_extension_check()

        self.exit_check()

        return 'xxx'


checker = DocChecking("Resources/DATASET/DocsCheck_2.eml")

#checker.metadata_check()
checker.macro_extension_check()