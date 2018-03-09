#!/usr/bin/env python3
'''
In dev...
'''
import re
import datetime
# Pattern definitions
datePattern = "([0-9:\-\ ,]{23})" #First 23 characters of the log line
IPPattern = ".*;oip=([0-9.]+);"

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

def parseEventType(logline):
    if "oip=" in logline:
        return True
    


filename = "audit.log"
with open(filename) as auditFile:
    for line in auditFile:
        if(parseEventType(line)):
            parsedIP = parseIP(line)
            print(parsedIP)
            parsedDate = (parseDate(line))
            if(parsedDate > (datetime.datetime.today() - datetime.timedelta(days=30))):
                pass
                #print (parsedDate)
