#from .main import Email  
from os import listdir, remove, path
from zipfile import ZipFile


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
        self.extensions: dict[str, str] = {}


    def _get_files(self):
        if not path.exists(self.document_path):
            return []
        else:
            # returns list of file names
            return [name for name in listdir(self.document_path) if path.isfile(path.join(self.document_path, name))]

    ################################### this should be extension extraction, then extension check should be checking against the first few bytes to determine the file extension
    def extension_check(self):
        self.extensions = {}

        for file_name in self.files:
            file_split = file_name.split('.')
            if len(file_split) > 2:
                # Placeholder risk flag
                print("RISKYYYYYYY")
                continue  # skip problematic files

            self.extensions[file_split[0]] = file_split[-1]

        return self.extensions

    # checking for macro
    def macro_extension_check(self):
        macro_extension = ['docm', 'xlsm', 'pptm', 'dotm']

        for file_name in self.extensions:
            if self.extensions[file_name] in macro_extension:
               ################################ change after done with risk score stuff
               # Will need to do further check
                print("RISKYYYYYYYYYYYYYY")

                print('macro_check')

        return

    def macro_check(self, file_name):
        # will usually contain vbaProject.bin
        with ZipFile(file_name) as z:
            if any("vbaProject.bin" in name for name in z.namelist()) == True:
                return "DANGERRRRRRRRRRRRRRRRRR"
        return

    # check if have any obfuscated content
    def obfuscated_check(self):
        for file_name in self.files:
            with open(f'{self.document_path}/{file_name}', 'rb') as file:
                raw = file.read()
            content = raw.decode('utf-8', errors='ignore')
            print(content)
            obfuscated_content = ''.join(filter(lambda s: s not in string.printable, content))
            print(obfuscated_content)
############################## will need to think of a better way to check for obfuscated content...
            if obfuscated_content != '':
                print('SUSS')
                return("SUSSSSSSSSSSSSSSSSS")

        return


    
    # always clear files after check
    def exit_check(self):
        for file_name in self.files:
            remove(f"{self.document_path}/{file_name}")

checker = DocChecking("Resources/DATASET/Project Proposal.eml")
print("\nREAL DEAL\n")

checker.obfuscated_check()
