#from .main import Email  
from socket import create_connection
from zipfile import ZipFile
from json import dumps, loads
from struct import unpack
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIAnalyses
from time import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

from os import listdir, remove, path
from LangAnalysis import Email

class DocChecking(Email):
    def __init__(self, email_path = None):
        super().__init__(email_path)

        self.document_path:str = 'Resources/TEMP_FILES'
        self.connectivity:[bool] = self.__internet_check()
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

    def __internet_check(self):
        try:
            create_connection(("www.google.com", 80), timeout=3)
            return True
        except Exception as e:
            print(e)
            return False  

    # extract wordlist
    # REMEMBER TO CHANGE FILE PATH
    def extract_wordlist(self, filename=None):
        with open(f'Resources/WORDLISTS/doc_check/{filename}', "r", encoding="utf-8") as f:
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
    def block_high_risk_files(self, files=None, extensions=None, root_file=None):

        files = files or self.files
        extensions = extensions or self.extensions

        wordlist = self.extract_wordlist('high_risk_extensions.txt')
        
        for files in extensions:
            # high risk extension detected
            if extensions[files] in wordlist:
                target_file = root_file or files
                self.file_score[target_file] += 1000000 # change to max score

        return True

    # check metadata dates [30]
    def metadata_check(self):

        for file_name in self.metadata_date:

            epoch_time = int(time())

            if self.metadata_date[file_name]['creation'] == self.metadata_date[file_name]['modified']:
                self.file_score[file_name] += 30

            elif self.metadata_date[file_name]['creation'] >= epoch_time or self.metadata_date[file_name]['modified'] >= epoch_time:
                self.file_score[file_name] += 30

        return False

    # checking for macro [10]
    def macro_extension_check(self):

        wordlist = self.extract_wordlist('macro_extensions.txt')
        
        for file_name in self.extensions:
            if self.extensions[file_name] in wordlist:
                self.file_score[file_name] += 10

                # check if macro exist in file
                macro_exist = self.macro_check(file_name)

                if macro_exist:
                    self.file_score[file_name] += 100

        return True

    # check if macro file contains macro [50]
    def macro_check(self, file_name):

        # will usually contain vbaProject.bin
        with ZipFile(f"{self.document_path}/{file_name}") as z:
            if any("vbaProject.bin" in name for name in z.namelist()) == True:
                return True

        return False

    # archive file check [10]
    def archive_check(self):
        
        wordlist = self.extract_wordlist('archive_extensions.txt')

        for file_name in self.files:
            
            # check if is archive extension
            if self.extensions[file_name] in wordlist:
                self.file_score[file_name] += 10

            # check if is .zip
            if self.extensions[file_name] == 'zip':
                content = self.archive_content_check(file_name)

                # if archive is password protected
                if content and content['encrypted'] == True:
                    self.file_score[file_name] += 10

                if content:
                    
                    # extract archive file extensions (only files)
                    archive_extension = {f: f.split('.')[-1] for f in content['filenames'] if '.' in f.split('/')[-1]}

                    # run block_high_risk_files
                    self.block_high_risk_files(files=content['filenames'], extensions=archive_extension, root_file=file_name)

        return True

    # encrypted archive file [10]
    def archive_content_check(self, file_name):

        result = {
            "encrypted": False,
            "filenames": []
        }

        with open(f'{self.document_path}/{file_name}', "rb") as f:
            data = f.read()

        i = 0
        # move byte by byte
        # https://en.wikipedia.org/wiki/ZIP_(file_format)#File_headers
        while i < len(data):
            if data[i:i+4] == b'PK\x03\x04':  # byte 1-4 = zip magic number (file header) - not empty
                flag = unpack("<H", data[i+6:i+8])[0] # byte 6-7 = general purpose bit flag [ZIP HEADER]

                # bit = 1 = not encrypted
                if flag & 0x1:
                    result["encrypted"] = True

                # find file name start byte
                fname_len = unpack("<H", data[i+26:i+28])[0] # byte 26-27 = number of bytes in filename
                extra_len = unpack("<H", data[i+28:i+30])[0] # byte 28-29 = number of bytes in extra field [ZIP METADATA]

                # from extra field [byte 30+n], search length of filename (fname_len)
                fname = data[i+30:i+30+fname_len].decode(errors="ignore")
                if fname:
                    result["filenames"].append(fname)

                # move on to the next file
                i += 30 + fname_len + extra_len

            else:
                # if is not header, move on
                i += 1

        if len(result['filenames']) != 0:
            return result
        else:
            return None

    # pip install vtapi3
    # check with virus total [50]
    def virus_total(self):
        if self.connectivity == False:
            return False

        API_KEY = '0f91624513c562fc371b980638f0bf815e54fa4e52e8fb763c29113d0d02947a'

        vt_files = VirusTotalAPIFiles(API_KEY)
        vt_analysis = VirusTotalAPIAnalyses(API_KEY)

        for file_name in self.files:
            try:
                # upload to virus total
                result = vt_files.upload(f"{self.document_path}/{file_name}")
                analysis_id = (loads(result))["data"]["id"]

                # get report
                report = vt_analysis.get_report(analysis_id)
                report_stats = (loads(report))['data']['attributes']['stats']
                
                # get highest rated field
                highest_score = max(report_stats, key=report_stats.get)
                
                match highest_score:
                    case 'malicious':
                        self.file_score[file_name] += 50
                    
                    case 'suspicious':
                        self.file_score[file_name] += 50

            # something went wrong
            except Exception as e:
                print(e)

        return True
   
    # always clear files after check
    def exit_check(self):
        for file_name in self.files:
            remove(f"{self.document_path}/{file_name}")

    def run_all_checks(self):
        self.block_high_risk_files()
        self.metadata_check()
        self.macro_extension_check()
        self.archive_check()

        if self.connectivity == False:
            self.virus_total()

        self.exit_check()

        return self.file_score, self.connectivity

# calculate risk score (score/total possible score)
def risk_score_calculate(file_risk_scores:dict, connectivity:bool):

    final_file_score = {file_name: 0 for file_name in file_risk_scores}

    if connectivity == True:
        max_score = 230
    else:
        max_score = 180

    for file_name, score in file_risk_scores.items():
        
        # high risk file present
        if score > max_score:
            percentage = 100
        else:
            percentage = score/max_score * 100
        final_file_score[file_name] = round(percentage, 2)

    print(final_file_score)
    return final_file_score

checker = DocChecking("Resources/DATASET/DocCheck3.eml")
file_score, internet_connection = checker.run_all_checks()
risk_score_calculate(file_score, internet_connection)