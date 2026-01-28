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
    #performs all default feild extractions
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
                        
        return plain_text,attachment_header,raw
    
    #extracts all headerfields from eml headers
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

#converts txt to data structure 
def init_file(path:str, conv_to_list:bool=False,inverse=False,encoding=None):
    output_dir = {}
    output_list = []
    with open(path,'r',encoding=encoding) as file:
        for line in file:
            if ',' in line:
                line = line.split(',')
            else:
                line = line.split()
            
            if conv_to_list:
                output_list.append(line)
            else:
                if inverse:
                    output_dir[line[1]] = line[0]
                else:
                    output_dir[line[0]] = line[1]

    if conv_to_list:
        return output_list
    else:
        return output_dir

def WordList_lemmatizer(word:str,wordlist={}):
    if word in wordlist:
        result = wordlist[word]
    else:
        result = word
    return result

def printable(string:str):
    return string.isprintable()

#strips, simplifies and tokenise words through a brute force of a lemmatizer word list
def tokenise(text:str):
    tokenised = []
    lines = text.split('\n')
    wordlist = init_file(path="Resources/WORDLISTS/tokenisation/lemmatization-en.txt",inverse=True,encoding="utf-8-sig")
    for line in lines:
        word_line = []
        line = list(filter(printable,line.split()))
        for word in line:
            word = re.sub('[^A-Za-z0-9]+', '', word)
            word_line.append(WordList_lemmatizer(word.lower(),wordlist=wordlist))
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

#initiates flag probability matrix from keyword folder by walking though all txt files in folder
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
def email_language_risk(email:Email=None,body=None,title=None,matrix={},total_weightage:int=40,base_confidence_score:int = 100):
    if email:
        text = email.text
        subject = email.subject
    else:
        text = body
        subject = title
    text = tokenise(f"{subject}\n{text}")
    risk_scores = {}
    #hardcoded values - to be replaced
    weight_multiplier = {
        0 : 1.4,
        1 : 1.3,
        3 : 1.2,
        5 : 1.1,
        8: 1.0
    }

    #determines probability of each flag in the matrix and multiplies it with the weightages of each line
    flag_weight = total_weightage / len(matrix.keys())
    for flag in matrix:
        frequency = {}
        keywords = matrix[flag]
        line_weight = weight_multiplier[0]
        flag_prob = 0
        
        for line in text:
            prob,frequency = detect_prob(line,keywords,frequency)
            if prob > 0:
                if text.index(line) in weight_multiplier:
                    line_weight = weight_multiplier[text.index(line)]
                flag_prob += prob * line_weight

        #calculates the counter-balances (confidence score) the flag probability
        confidence_score = base_confidence_score - calc_confidence(frequency,keywords)

        #total text length modifier
        if len(text) < 300:
            length_modifier = 1.2
        else:
            length_modifier = 1

        if flag_prob > 100:
            flag_prob = 100

        risk_scores[flag] = round(flag_weight * (flag_prob/100) * (confidence_score/100) * length_modifier,2)
    return risk_scores

#subtracts word probability distribution of flagged words from the risk scores 
def calc_confidence(data:dict,model:dict):
    #probibility of all data points
    frequency = {}
    total_occurances = sum(data.values())
    for item in data:
        frequency[item] = data[item]/total_occurances * 100

    #sum of delta of probability of datapoints and risk scores
    diff = 0
    for item in frequency:
        if data[item] > 3:
            diff += ((model[item] - frequency[item]) ** 2) ** 0.5
    return diff

#calculates probability of the text matching the flag and the frequency of keywords/phrases
#iteratively checks each word and subsequent words for matches to keywords or phrases
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
        else:
            #check of keyphrases
            for length in range(1,len(max_phrase.split())+1):
                words = text[index:index+length]
                if len(words) > 1:
                    phrase_list = " ".join(words)
                    if phrase_list in keywords.keys():
                        probability += keywords[phrase_list]
                        frequency = increment_frequncy(frequency,phrase_list)
    return probability, frequency

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
matrix = init_keyword_matrix()
scores = email_language_risk(body=malic,title=malic_sub,matrix=matrix)
print(scores)

