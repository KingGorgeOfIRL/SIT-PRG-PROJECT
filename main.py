import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
class Email:
    body = ""
    subject = ""
    sender = ""
    header = ""
    raw = None
    def __init__(self,email:str=None,attachments:dict=None):
        extracted = self.extract(email,attachments)
        self.body = extracted[0]
        self.subject = extracted[1]
        self.sender = extracted[2]
        self.header = extracted[3]
        self.raw = email
    
    #extraction logic for eml files 
    def Extract_eml(email_path:str=None):
        text = ""
        title = ""
        sender = ""
        header = ""
        with open(email_path,'rb') as file:
            raw = BytesParser(policy=policy.default).parse(file)
        #removes HTML tags 
        body = raw.get_body().get_content()
        text = BeautifulSoup(body,"lxml").text
        title = raw['subject']
        sender = raw['from']
        header = raw['header']

        return (text,title,sender,header,raw)

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


