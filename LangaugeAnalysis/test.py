from LangaugeAnalysis.mail import Email

mail = Email("Resources/DATASET/story.eml")
for text in mail.text:
    if text == '\n':
        print('newline character')