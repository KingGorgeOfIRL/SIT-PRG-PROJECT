def init_wordlist(path:str = "Resources/WORDLISTS/lemmatization-en.txt"):
    wordlist = {}
    with open(path,'r',encoding="utf-8-sig") as file:
        for line in file.readlines():
            line = line.split()
            wordlist[line[1]] = line[0]
    return wordlist

print(init_wordlist())