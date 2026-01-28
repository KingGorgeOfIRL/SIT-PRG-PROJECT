import os
from email import policy
from email.parser import Parser, HeaderParser
from html.parser import HTMLParser
from io import StringIO
import base64
import re
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

def init_file(path:str, conv_to_list:bool=False, auto_conv_type=False):
    output_dir = {}
    output_list = []
    with open(path,'r') as file:
        for line in file:
            line = line.split(',')
            if conv_to_list:
                output_list.append(line)
            else:
                output_dir[line[0]] = line[1].strip()

    if conv_to_list:
        return output_list
    else:
        return output_dir

class Lemmatizer:
    def __init__(self):
        return

    def init_wordlist(self,path:str = "Resources/WORDLISTS/tokenisation/lemmatization-en.txt"):
        wordlist = {}
        with open(path,'r',encoding="utf-8-sig") as file:
            for line in file.readlines():
                line = line.split()
                wordlist[line[1]] = line[0]
        return wordlist
    
    def WordList_lemmatizer(self,word:str):
        self.wordlist = self.init_wordlist()
        if word in self.wordlist:
            result = self.wordlist[word]
        else:
            result = word
        return result
    
#strips, simplifies and tokenise words 
def tokenise(text:str):
    lemmatizer = Lemmatizer()
    lemmatizer.init_wordlist()
    tokenised = []
    lines = text.split('\n')
    for line in lines:
        word_line = []
        for word in line.split():
            if word.isprintable():
                word = re.sub('[^A-Za-z0-9]+', '', word)
                word_line.append(lemmatizer.WordList_lemmatizer(word.lower()))
        if word_line:
            tokenised.append(word_line)
    if len(tokenised) == 1:
        return word_line
    else:
        return tokenised

def increment_frequncy(frequency:dict,item):
    if item in frequency:
        frequency[item] += 1
    else:  
        frequency[item] =1
    return frequency

#calculates the probability of the text matching the flag and the frequency of keywords/phrases
def detect_prob(text:list,keywords:dict,frequency:dict={}):
    probability = 0
    max_phrase = ""
    for key in keywords.keys():
        if len(key.split()) > len(max_phrase.split()):
            max_phrase = key

    for index in range(len(text)):
        #check of individual keywords
        if text[index] in keywords.keys():
            probability += keywords[text[index]]
            frequency = increment_frequncy(frequency,text[index])

        #check of keyphrases
        for length in range(1,len(max_phrase.split())+1):
            words = text[index:index+length]
            if len(words) > 1:
                phrase_list = " ".join(words)
                if phrase_list in keywords.keys():
                    probability += keywords[phrase_list]
                    frequency = increment_frequncy(frequency,phrase_list)
    return probability, frequency

#initiates flag probability matrix from keyword folder
def init_keyword_matrix(keyword_folder_path:str="Resources/WORDLISTS/language_analysis"):
    matrix = {}
    for (dirpath,dirname,filenames) in os.walk(keyword_folder_path):
        for filename in filenames:
            name = filename.split('.')[0]
            keywords = init_file(os.path.join(dirpath,filename))
            temp_dict = {}
            for key in keywords:
                temp_key = " ".join(tokenise(key))
                temp_dict[temp_key] = float(keywords[key])
            matrix[name] = temp_dict
    return matrix

#total language risk score
def email_language_risk(email:Email=None,body=None,title=None,total_weightage:int=40,base_confidence_score:int = 100):
    if email:
        text = email.text
        subject = email.subject
    else:
        text = body
        subject = title
    text = tokenise(f"{subject}\n{text}")
    risk_scores = {}
    matrix = init_keyword_matrix()
    #hardcoded values - to be replaced
    weight_multiplier = {
        0 : 1.4,
        1 : 1.3,
        3 : 1.2,
        5 : 1.1,
        8: 1.0
    }

    #determines probability of each flag in the matrix and multiplies it with the weightages of each line
    frequency = {}
    flag_weight = total_weightage/len(matrix.keys())
    for flag in matrix:
        keywords = matrix[flag]
        line_weight = weight_multiplier[0]
        flag_prob = 0
        
        for line in text:
            prob,frequency = detect_prob(line,keywords,frequency)
            if prob > 0:
                if text.index(line) in weight_multiplier:
                    line_weight = weight_multiplier[text.index(line)]
                flag_prob += prob * line_weight

        if flag_prob > 100:
            flag_prob = 100

        # confidence_score = base_confidence_score - calc_confidence(frequency,keywords)
        # if confidence_score < 0:
        #     confidence_score = 0

        risk_scores[flag] = flag_weight * (flag_prob/100)# * (confidence_score/100)
    return round(risk_scores,2), frequency

def calc_confidence(data:dict,model:dict):
    #probibility of all data points
    frequency = {}
    total_occurances = sum(data.values())
    for item in data:
        frequency[item] = data[item]/total_occurances * 100

    #sum of delta of probability of datapoints and risk scores
    diff = 0
    for item in frequency:
        if frequency[item] > 3:
            diff += ((model[item] - frequency[item]) ** 2) ** 0.5
    return diff


normal = "Resources/DATASET/story.eml"
malic_sub = "Payment Declined – Urgent Request from Finance Team"
malic = """
Hello,

Your recent invoice payment was declined due to a billing error. Please download the attached file and follow the instructions to update your account immediately.

If we do not receive your confirmation within 24 hours, your account may be flagged for non-compliance and subject to temporary suspension.

For your protection, do not share this message externally.

Best regards,
Compliance Department
Internal IT Support
"""
mail = Email(normal)
#scores = email_language_risk(email=mail)
scores = email_language_risk(body=malic,title=malic_sub)
print(scores)
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


#to do: init txts to dicts and lists, modifiers, score calculator 
"""
testcases:
confidence score
"""