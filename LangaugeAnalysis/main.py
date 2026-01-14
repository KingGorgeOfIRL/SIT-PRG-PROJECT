from .main import Email  
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

