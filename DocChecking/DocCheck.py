#from .main import Email  
from magic import *
from size import *
from zipfile import ZipFile
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
                print("attachment found",part.get('Content-Disposition'))
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
        self.files:list[str] = self._get_files()
        self.extensions: dict[str, str] = self._extension_extraction()
        self.file_size:int = (int(self.attachment_header[0]['size=']) / 1024) # convert to bytes
        self.creation_date_epoch:int = self._date_extraction()[0]
        self.modified_date_epoch:int = self._date_extraction()[1]


    def _get_files(self):
        if not path.exists(self.document_path):
            return []
        else:
            # returns list of file names
            return [name for name in listdir(self.document_path) if path.isfile(path.join(self.document_path, name))]

    def _extension_extraction(self):
        extensions = {}

        for file_name in self.files:
            file_split = file_name.split('.')
            if len(file_split) > 2:
                # Placeholder risk flag
                print("RISKYYYYYYY")

            extensions[file_split[0]] = file_split[-1]

        return extensions

    
    # depending on the email class dk if it will have multiple
    def _date_extraction(self):
        creation_date_epoch = self.to_epoch_time(self.attachment_header[0]['creation-date='])
        modified_date_epoch = self.to_epoch_time(self.attachment_header[0]['modification-date='])
        return [creation_date_epoch, modified_date_epoch]

    # blocks executables
    def block_high_risk_files(self):
        BLOCKED_EMAIL_EXTENSIONS = ["exe", "com", "bat", "cmd", "scr", "pif", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "msi", "msp", "dll", "sys", "cpl","jar", "iso", "img", "apk"]
        
        for files in self.extensions:
            if self.extensions[files] in BLOCKED_EMAIL_EXTENSIONS:
                print("BLOCKEDDDDDD")
                return 0
            return 1

    ################################### see if the logic make sense... or can add more when it comes to mind
    def metadata_check(self):
        epoch_time = int(time.time())

        if self.creation_date_epoch == self.modified_date_epoch:
            print("SUSSSSSSSSSSSSSSSSSSSSSSS")
            return
        
        elif self.creation_date_epoch >= epoch_time or self.modified_date_epoch >= epoch_time:
            print("SUSSSSSSSSSSSSSSSSSSSSSSS")
            return


    # convert date string to epoch (metadata check)
    def to_epoch_time(self, date: str):
        dt = parsedate_to_datetime(date)

        # if timezone is missing, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)

        return int(dt_utc.timestamp())

    # checks first few bytes to confirm extension
    def extension_check(self):
        for files in self.extensions:
            with open(f'{self.document_path}/{files}.{self.extensions[files]}', 'rb') as f:
                print(f'{self.document_path}/{files}.{self.extensions[files]}')
                data_bytes = f.read()
                print(data_bytes)


    def magic_number_check(self):
        for files in self.extensions:
            with open(f'{self.document_path}/{files}.{self.extensions[files]}', 'rb') as fb:
                raw = fb.read()

            ################################################### ADD MORE EXTENSION!!!!!!!!!!!!!!!!!!
            match (self.extensions[files]):
                case 'docx' | 'xlsx' | 'pptx':
                    if raw.startswith(MS_OFFICE_MAGIC):
                        return 1
                    # can probably add more logic here, c how i wanna settle it
                    return 0
                
                # file extension not suppoerted to check
                case _:
                    print('end')


    # check if file size is sussss
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

    # checking for macro
    def macro_extension_check(self):
        macro_extension = ['docm', 'xlsm', 'pptm', 'dotm']

        for file_name in self.extensions:
            if self.extensions[file_name] in macro_extension:
               ################################ change after done with risk score stuff
               # Will need to do further check
                print("RISKYYYYYYYYYYYYYY")

                # see how i wanna send back the risk data if have macro
                self.macro_check(file_name)

        return

    def macro_check(self, file_name):
        # will usually contain vbaProject.bin
        with ZipFile(file_name) as z:
            if any("vbaProject.bin" in name for name in z.namelist()) == True:
                return "DANGERRRRRRRRRRRRRRRRRR"
        return

   
    # always clear files after check
    def exit_check(self):
        for file_name in self.files:
            remove(f"{self.document_path}/{file_name}")

checker = DocChecking("Resources/DATASET/Project Proposal.eml")
print("\nREAL DEAL\n")

#checker.metadata_check()
checker.block_high_risk_files()