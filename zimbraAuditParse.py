#!/usr/bin/env python3
'''
In dev...
'''
import re
import datetime
# Pattern definitions
datePattern = "([0-9:\-\ ,]{23})" #First 23 characters of the log line
IPPattern = ".*;oip=([0-9.]+);"
accountPattern = "account=([\w\.\@]+);"
protocolPattern = "protocol=(soap|imap|pop3)"

def parseDate(logLine):

    dateResult = re.search(datePattern,logLine)
    if(dateResult):
        eventDateStr = dateResult.group(1)
        dateObject = datetime.datetime.strptime(eventDateStr,"%Y-%m-%d %H:%M:%S,%f")
        return dateObject
    else:
        return False
def parseIP(logLine):
    IPResult = re.search(IPPattern,logLine)
    if (IPResult):
        IPResult=IPResult.group(1)
        return IPResult
    return False
def parseAccount(logline):
    accountResult = re.search(accountPattern,logline)
    if (accountResult):
        accountResult = accountResult.group(1)
        return accountResult
    return False
def parseProtocol(logline):
    protocolResult = re.search(protocolPattern,logline)
    if (protocolResult):
        protocolResult = protocolResult.group(1)
        if("oproto=smtp" in logline):
            return "smtp"
        if (":8080" in logline):
            return "web"
        return protocolResult
    return False
def parseEventState(logline):
    if "WARN" in logline:
        eventState = "fail"
    else:
        return "success"
    if "invalid password" in logline:
        eventState = "invalid password"
    return eventState      
def parseEventType(logline):
    if "oip=" in logline:
        return True    


filename = "audit.log"
with open(filename) as auditFile:
    for line in auditFile:
        if(parseEventType(line)):
            parsedDate = (parseDate(line))
            if(parsedDate > (datetime.datetime.today() - datetime.timedelta(days=30))):
                pass
                #print (parsedDate
            #parsedDate
            parsedIP = parseIP(line)
            parsedAccount = parseAccount(line)
            parsedProtocol = parseProtocol(line)
            parsedState = parseEventState(line)
            #print(parsedDate,parsedIP,parsedAccount,parsedProtocol,parsedState)         