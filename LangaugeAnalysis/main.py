import os
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
    
    def __bs64_save_attachments(self,base64str:str,header_data:str,output_path:str="LangaugeAnalysis/Resources/TEMP_FILES"):
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
        with open(f"{output_path}/{name}", "wb") as f:
            f.write(file_bytes)
        return meta_data

    def __repr__(self):
        return f"Email<Subject:{self.subject},Sender:{self.sender}>"

class Lemmatizer:
    def __init__(self):
        return

    def init_wordlist(self,path:str = "Resources/WORDLISTS/lemmatization-en.txt"):
        wordlist = {}
        with open(path,'r',encoding="utf-8-sig") as file:
            for line in file.readlines():
                line = line.split()
                wordlist[line[1]] = line[0]
        return wordlist
    
    def WordList_lemmatizer(self,word:str):
        self.wordlist = self.init_wordlist()
        result = self.wordlist[word]
        return result

class LanguageAnalysis(Email):
    def __init__(self, email_path = None):
        super().__init__(email_path)
        self.keyword_folder_path:str = '' #change once genKeywords is finished
        self.positional_path:str = ''#change once genKeywords is finished

    #initiates weighted keyword files from file paths
    def init_file(self,path:str):
        keywords:dict = {}
        with open(path,'r') as file:
            lines= file.readlines()
        for line in lines:
            text,score = line.split(',')
            keywords[self.tokenise(text)] = int(score)
        return keywords

    #calculates the probability of the text matching the flag
    def detect_prob(self,text:list,keywords:dict):
        probability = 0
        max_phrase_size = len(max(keywords.keys(),key=len))
        for index in range(len(text)):
            #check of individual keywords
            if [text[index]] in keywords.keys():
                probability += keywords[text[index]]

            #check of keyphrases
            for length in range(max_phrase_size):
                phrase_list = [text[index:index+length]]
                if phrase_list in keywords.keys():
                    probability += keywords[phrase_list]
        return probability
    
    def multipliers(self,flagged_text:dict,positional_weightage:dict,subject=False):
        #positional multipliers
        if subject:
            pass
        else:
            pass
        return

    #sums the flagged scores
    def score(self,flagged:dict):
        score = 0
        for item in flagged:
            score += flagged[item]
        return score

    #total language risk score
    def language_risk_score(self,subject:str,text:str,folder_path:str=None):
        #initiates flag probability matrix from keyword folder
        if not folder_path:
            folder_path = self.keyword_folder_path
        matrix = {}
        for (dirpath,dirname,filenames) in os.walk(folder_path):
            for filename in filenames:
               matrix[filename.split('.')[0]]=self.init_file(os.path.join(dirpath,filename))
        
        flagged_body = {}
        flagged_subject = {}
        text = self.tokenise(text)
        for flag in matrix:
            keywords = matrix[flag]
            for line in text:
                flagged_body[flag].update((self.detect_flag(line,keywords)))
                flagged_subject[flag].update(self.detect_flag(subject,keywords))
        #determines probability of each flag in the matrix 


        #multipliers
        ## position of word
        
    #strips, simplifies and tokenise words 
    def tokenise(self,text:str):
        lemmatizer = Lemmatizer()
        tokenised = []
        lines = text.split('\n')
        for line in lines:
            word_line = []
            for word in line.split():
                word_line.append(lemmatizer.WordList_lemmatizer(word))
            tokenised.append(word_line)
        return tokenised


#stucture of keyphrase and key words is <word/words> , <score>
"""
matrix = {
urgancy:{
word1:probability1,
phrase2:probability2
},
call-to-action:{
word1:probability1,
phrase2:probability2
}
}
"""
