logFile = r"D:\honeypot\code\python\logs\cowrieTest.json" #will need to be changed obvs

def getFile():
    with open(logFile) as lf:
        #Opens the text file and places all text in lf varible
        lf = lf.readlines()
    breakDownData(lf)

def breakDownData(logData):
    x = 0
    for y in logData:
        line = logData[x]
        eLoc = line.find('"eventid":') + 10
        nELoc = line.find('"}', eLoc)
        eventId = line[eLoc:nELoc]
        print(eventId)
        x = x + 1

getFile()