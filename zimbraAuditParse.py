#!/usr/bin/env python3
'''
In dev...
'''
import re
import datetime
# Pattern definitions
datePattern = "([0-9:\-\ ,]{23})" #First 23 characters of the log line



def parseDate(logLine):

    dateResult = re.search(datePattern,logLine)
    if(dateResult):
        eventDateStr = dateResult.group(1)
        dateObject = datetime.datetime.strptime(eventDateStr,"%Y-%m-%d %H:%M:%S,%f")
        #dateobdateObject.isoformat(timespec="milliseconds")
        return dateObject
    else:
        return False    

filename = "audit.log"
with open(filename) as auditFile:
    for line in auditFile:
        parsedDate = (parseDate(line))
        if(parsedDate > (datetime.datetime.today() - datetime.timedelta(days=30))):
            print (parsedDate)