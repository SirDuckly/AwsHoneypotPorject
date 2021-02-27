#TODO
# 1. Read thing
# 2. Place into database
# 3. Work out how to define "Attacks"
#WORKED OUT
# 1. Attacks should be per session ID

#LIST
#Store data in table
#Another table to store run info (any misses, what were they, time script ran)
#Save scirpt data in txt - DONE
#Read script data - NEXT

#This script reads the json log file
import time
from datetime import datetime

missed = 0
run = [1]
missedIds = []

#Log file name can stay the same as cowrie uses "cowrie.json" for its most recent activity #USEFUL
def getLine():
    logFile = r"C:\Documents\Projects\honeypot\code\python\logs\1Line.json" #will need to be changed obvs
    with open(logFile, 'r+') as log:
        line = log.readline()
        lineNo = 1
        while line:
            breakDownData(line, lineNo)
            lastLine = line
            line = log.readline()
            lineNo = lineNo + 1
        log.close()
        getScriptData(lastLine)
        print("Missed lines: ", missed)

def saveScriptData(scriptData, runNo, lastLine):
    global missed
    global missedIds
    now = datetime.now()
    currDate = now.strftime("%d/%m/%Y")
    currTime = now.strftime("%H:%M:%S")
    appendData = open(scriptData, 'a')
    appendData.write('runNum="' + str(runNo) +'"\n')
    appendData.write('dateRan="' + currDate + '"\n')
    appendData.write('timeRan="' + currTime + '"\n')
    appendData.write('missedLines="' + str(missed) +'"\n')
    appendData.write('lastLine=' + lastLine + '\n') #data.find("\n")
    appendData.write(r'</-----LOG_BREAK-----\>')

def getScriptData(lastLine):
    global run
    scriptData = r"C:\Documents\Projects\honeypot\code\python\scriptData\scriptData.txt"
    readData = open(scriptData, 'r')
    line = readData.readline()
    if line.find('runNum="') != -1:
        for line in readData:
            runNo = findRunNo(line)
            run.append(runNo)
            line = readData.readline()
        #if run[0] != 0:
        runNumber = max(run) + 1
        #else:
         #   run[0] = 1
        saveScriptData(scriptData,runNumber, lastLine)
        readData.close()
    else:
        saveScriptData(scriptData, 1, lastLine)
        readData.close()

def findRunNo(line):
    rLoc = line.find('runNum="') + 8
    nRLoc = line.find('"', rLoc)
    runNo = line[rLoc:nRLoc]
    return(runNo)

def breakDownData(line, lineNo):
    if line.find('"cowrie.session.connect"') != -1:
        print("Cowrie 1 Connect:")
        print(findSession(line))
        print(findIp(line))
        print(findTime(line))
        print(findProtocol(line))
        print("\n")
    elif line.find('"cowrie.session.params"') != -1:
        print("Cowrie 2 params:")
        print(findSession(line))
        print(findArch(line))
        print(findIp(line))
        print(findTime(line))
        print("\n")
    elif line.find('"cowrie.session.file_download"') != -1:
        print("Cowrie 3 file_download:")
        print(findSession(line))
        print(findIp(line))
        print(findTime(line))
        print(findOutfile(line))
        print(findDest(line))
        print(findUrl(line))
        print(findMessageV2(line))
        print('\n')
    elif line.find('"cowrie.session.closed"') != -1:
        print("Cowrie 3.1 closed:", lineNo)
        print(findSession(line))
        print(findIp(line))
        print(findDuration(line))
        print(findMessageV2(line))
        print(findTime(line))
        print("\n")
    elif line.find('"cowrie.login.success"') != -1:
        print("Cowrie 4 success:")
        print(findSession(line))
        print(findIp(line))
        print(findUser(line))
        print(findPass(line))
        print(findMessage(line))
        print(findTime(line))
        print("\n")
    elif line.find('"cowrie.login.failed"') != -1:
        print("Cowrie 5 failed:")
        print(findUser(line))
        print(findPass(line))
        print(findSession(line))
        print(findMessage(line))
        print(findIp(line))
        print(findTime(line))
        print("\n")
    elif line.find('"cowrie.command.input"') != -1:
        print("Cowrie 6 input:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findInput(line))
        print(findMessageV2(line))
        print("\n")
    elif line.find('"cowrie.command.success"') != -1:
        print("Cowrie 7 log command success:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findInput(line))
        print(findMessageV2(line))
        print("\n")
    elif  line.find('"cowrie.command.failed"') != -1:
        print("Cowrie 8 command failed:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findInput(line))
        print(findMessageV2(line))
        print("\n")
    elif line.find('"cowrie.direct-tcpip.request"') != -1:
        print("Cowrie 9 tcp ip request:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findDstPort(line))
        print(findDstIp(line))
        print(findMessage(line))
        print("\n")
    elif line.find('"cowrie.direct-tcpip.data"') != -1:
        print("Cowrie 10 direct tcpData:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findDstPort(line))
        print(findDstIpV2(line))
        print(findMessage(line))
        print("\n")
    elif line.find('"cowrie.client.version"') != -1:
        print("Cowrie 11 client version:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findMessageV2(line))
        print("\n")
    elif line.find('"cowrie.client.kex"') != -1:# key exchange
        print("Cowrie 12 client kex:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findMessageV3(line))
        print("\n")
    elif line.find('"cowrie.log.closed"') != -1:
        print("Cowrie 13 log closed:")
        print(findSession(line))
        print(findTime(line))
        print(findIp(line))
        print(findMessage(line))
        print("\n")
    else:
        global missedIds
        global missed
        eLoc = line.find('"eventid":"') + 11
        nELoc = line.find('"}', eLoc)
        eventId = line[eLoc:nELoc]
        print(eventId, "line: ", lineNo)
        missedIds.append(eventId)
        missed = missed + 1

def findSession(line):
    #The + after the find is to offset the fact find() returns the value to the first character
    sLoc = line.find('"session":') + 11
    nSLoc = line.find('"', sLoc)
    session = line[sLoc:nSLoc]
    return(session)

def findProtocol(line):
    pLoc = line.find('"protocol":') + 12
    nPLoc = line.find('",', pLoc)
    protocol = line[pLoc:nPLoc]
    return(protocol)

def findArch(line):
    aLoc = line.find('"arch":') + 8
    nALoc = line.find('","message":', aLoc)
    arch = line[aLoc:nALoc]
    return(arch)

def findDuration(line):
    dLoc = line.find('"duration":') + 11
    nDLoc = line.find(',', dLoc)
    duration = line[dLoc:nDLoc]
    return(duration)

def findIp(line):
    ipLoc = line.find('"src_ip":') + 10
    nIpLoc = line.find('"', ipLoc)
    ip = line[ipLoc:nIpLoc]
    return(ip)

def findTime(line):
    tLoc = line.find('"timestamp":') + 13
    nTLoc = line.find('"', tLoc)
    timestamp = line[tLoc:nTLoc]
    return(timestamp)

def findInput(line):
    iLoc = line.find('"input":') + 9
    nILoc = line.find('","session":', iLoc)
    userInput = line[iLoc:nILoc]
    return(userInput)

#Really annoying but sadly the log file isnt consitent like everything else 
def findMessage(line):
    mLoc = line.find('"message":') + 11
    nMLoc = line.find('","src_ip":', mLoc)
    message = line[mLoc:nMLoc]
    return(message)

def findMessageV2(line):
    mLoc = line.find('"message":') + 11
    nMLoc = line.find('","eventid":', mLoc)
    message = line[mLoc:nMLoc]
    return(message)

def findMessageV3(line):
    mLoc = line.find('"message":') + 11
    nMLoc = line.find('","keyAlgs":', mLoc)
    message = line[mLoc:nMLoc]
    return(message)
''''
def findData(line):
    dLoc = line.find('"data":') + 8
    nDloc = line.find('","src_ip":', dLoc)
    data = line[dLoc:nDloc]
    return(data)'''

def findUser(line):
    uLoc = line.find('"username":') + 12
    nULoc = line.find('","session":"', uLoc)
    user = line[uLoc:nULoc]
    return(user)

def findPass(line):
    pLoc = line.find('"password":') + 12
    nPLoc = line.find('","message":', pLoc)
    password = line[pLoc:nPLoc]
    return(password)

def findDstPort(line):
    dpLoc = line.find('"dst_port":') + 11
    nDpLoc = line.find(',"', dpLoc)
    dstPort = line[dpLoc:nDpLoc]
    return(dstPort)

def findDstIp(line):
    dIpLoc = line.find('"dst_ip":') + 10
    nDIpLoc = line.find('","message":', dIpLoc)
    dstIp = line[dIpLoc:nDIpLoc]
    return(dstIp)

def findDstIpV2(line):
    dIpLoc = line.find('"dst_ip":') + 10
    nDIpLoc = line.find('","id":', dIpLoc)
    dstIp = line[dIpLoc:nDIpLoc]
    return(dstIp)

def findOutfile(line):
    oFLoc = line.find('"outfile":') + 11
    nOFLoc = line.find('","session"', oFLoc)
    outFile = line[oFLoc:nOFLoc]
    return(outFile)

def findDest(line):
    dLoc = line.find('"destfile":') + 12
    nDLoc = line.find('","sensor":', dLoc)
    destination = line[dLoc:nDLoc]
    return(destination)

def findUrl(line):
    urlLoc = line.find('"url":') + 7
    nUrlLoc = line.find('","src_ip":', urlLoc)
    url = line[urlLoc:nUrlLoc]
    return(url)

'''
v = 0
while v <= 9:
v = v + 1
'''
start = time.time()
getLine()
end = time.time()
print("Elapsed time: ", end - start)