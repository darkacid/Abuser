#!/usr/bin/env python3
'''
In dev...
'''
import re
import datetime
# Pattern definitions
datePattern = "([0-9:\-\ ]{19})"



def parseLine(logLine):

    dateResult = re.search(datePattern,logLine)
    if(dateResult):
        eventDateStr = dateResult.group(1)
        dateObject = datetime.datetime.strptime(eventDateStr,"%Y-%m-%d %H:%M:%S")
        return dateObject
    else:
        return False    


with open("audit.log") as auditFile:
    for line in auditFile:
        print (parseLine(line))