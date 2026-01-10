from email import policy
from email.parser import BytesParser, HeaderParser
from bs4 import BeautifulSoup
from string import printable
class Email:
    def __init__(self,email_path:str=None):
        headers = self.__extract_headers(email_path)
        self.text:str = self.__extract_body(email_path)[0]
        self.raw = self.__extract_body(email_path)[1]
        self.subject:str = headers['Subject'] 
        self.sender:str = headers['From'] 
        self.header = headers 
    
    def __extract_body(self,email_path:str=None):
        with open(email_path,'rb') as file:
            raw = BytesParser(policy=policy.default).parse(file)
        #removes HTML tags 
        body = raw.get_body().get_content()
        txt:str = BeautifulSoup(body,"lxml").text
        txt = "\n".join(item for item in txt.split('\n') if item)
        return txt,raw
    
    def __extract_headers(self,email_path:str=None):
        with open(email_path,'r') as file:
            raw = HeaderParser().parse(file)
        raw_dict = {}
        for item in raw.items():
            raw_dict[item[0]] = item[1]
        return raw_dict
    
    def __repr__(self):
        return f"Email<Subject:{self.subject},Sender:{self.sender}>"

def detect_keyword(text:str="",keywords:list=[],keyphrases:list=[]):
    words = text.split(' ')
    max_phrase_size = len(max(keyphrases,key=len).split(' '))
    flagged = {}
    for index in range(len(words)):
        if words[index] in keywords:
            flagged[index] = "keyword:" + words[index]
        for length in range(max_phrase_size):
            phrase = " ".join(words[index:index+length])
            if phrase in keyphrases:
                flagged[f"{index}:{index+length}"] = "keyphrase" + phrase
    return flagged, text

def keyword_positioning(text:str="",flagged:dict={}):
    return


def init_keywords_and_phrases(FilePath:str = ''):
    keywords = []
    keyphrases = []
    return keywords, keyphrases


