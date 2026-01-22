from .main import Email  
import os
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

    #flags suspicous words and attached probability
    def detect_flag(self,text:str,keywords:dict):
        words = self.tokenise(text)
        word_dict = {}
        max_phrase_size = len(max(keywords.keys(),key=len))
        for index in range(len(words)):
            #check of individual keywords
            if [words[index]] in keywords.keys():
                word_dict[index] = [index,keywords[words[index]]]

            #check of keyphrases
            for length in range(max_phrase_size):
                phrase_list = [words[index:index+length]]
                if phrase_list in keywords.keys():
                    word_dict[index] = [index+length,keywords[phrase_list]] # i.e., start_index : [end_index,score] 
        return word_dict
    
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
        
        #determines probability of each flag in the matrix 
        flagged_body = {}
        flagged_subject = {}
        for flag in matrix:
            keywords = matrix[flag]
            flagged_body[flag] = self.detect_flag(text,keywords)
            flagged_subject[flag] = self.detect_flag(subject,keywords)

        #multipliers
        

        
    #strips, simplifies and tokenise words 
    def tokenise(self,text:str):
        lemmatizer = Lemmatizer()
        tokenised = []
        for word in text.split():
            tokenised.append(lemmatizer.WordList_lemmatizer(word))
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
