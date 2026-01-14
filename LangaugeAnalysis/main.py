from email import policy
from email.parser import BytesParser, HeaderParser
from bs4 import BeautifulSoup
import nltk
from nltk.stem import WordNetLemmatizer
from string import printable
#instanciates and downloads lennatizer liberary 
try:
    nltk.data.find('wordnet')
except:
    nltk.download('wordnet',"LangaugeAnalysis/Resources/NLTK")

class Email:
    def __init__(self,email_path:str=None):
        headers = self.__extract_headers(email_path)
        self.text:str = self.__extract_body(email_path)[0]
        self.raw = self.__extract_body(email_path)[1]
        self.subject:str = headers['Subject'] 
        self.sender:str = headers['From'] 
        self.header:dict = headers 
        self.email_path:str = email_path

    #extracts all body text free of HTML tags
    def __extract_body(self):
        with open(self.email_path,'rb') as file:
            raw = BytesParser(policy=policy.default).parse(file)
        #removes HTML tags 
        body = raw.get_body().get_content()
        txt:str = BeautifulSoup(body,"lxml").text
        txt = "\n".join(item for item in txt.split('\n') if item)
        return txt,raw
    
    #extract all email headers as a dictionary
    def __extract_headers(self):
        with open(self.email_path,'r') as file:
            raw = HeaderParser().parse(file)
        raw_dict = {}
        for item in raw.items():
            raw_dict[item[0]] = item[1]
        return raw_dict
    
    def __extract_attachments(self):
        return

    def __repr__(self):
        return f"Email<Subject:{self.subject},Sender:{self.sender}>"
           
class LanguageAnalysis(Email):
    def __init__(self, email_path = None):
        super().__init__(email_path)
        #initiate LLM GenKeyWords here
        
        self.keyword_path:str = '' #change later
        self.keyphrase_path:str = '' #change once genKeywords is finished

    #initiates weighted keyword files from file paths
    def __init_file(self,path:str=''):
        keywords:dict = {}
        with open(path,'r') as file:
            lines= file.readlines()
        for line in lines:
            text,score = line.split(',')
            keywords[self.tokenise(text)] = int(score)
        return keywords
        #total scoring of language risk
    
    #total language risk score
    def language_risk_score(self):
        keywords = self.__init_file(self.keyword_path)
        keyphrases = self.__init_file(self.keyphrase_path)
        self.risk_score:int = self.__score(self.__detect_suspect(self.subject,keywords,keyphrases)) * 1.4 + self.__score(self.__detect_suspect(self.text,keywords,keyphrases)) 
        return self.risk_score
    
    #strips, simplifies and tokenise words 
    def tokenise(self,text:str):
        lemmatizer = WordNetLemmatizer()
        tokenised = []
        for word in text.split():
            tokenised.append(lemmatizer.lemmatize(word))
        return tokenised

    #flags suspect words/phrases in respect to its overall index for transparency reconstruction along with its calculated score
    def __detect_suspect(self,text:str="",keywords:dict={},keyphrases:dict={}):
        words = self.tokenise(text)
        max_phrase_size = len(max(keyphrases.keys(),key=len))
        flagged = {}
        for index in range(len(words)):
            if [words[index]] in keywords.keys():
                flagged[index] = (words[index],keywords[words[index]])
            for length in range(max_phrase_size):
                phrase_list = [words[index:index+length]]
                if phrase_list in keyphrases.keys():
                    flagged[index] = (phrase_list,keyphrases[phrase_list])
        return flagged

    #sums the flagged scores
    def __score(self,flagged:dict):
        score = 0
        for item in flagged:
            score += flagged[item]
        return score

#stucture of keyphrase and key words is <word/words> , <score>

