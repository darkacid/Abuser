#!/usr/bin/env python3
'''
Inf dev...
'''
import re
import datetime
import threading
import time
import os
import signal

import abuseipdbCheck
from logread import logread
from config import config
from iptables import iptables
# Pattern definitions
datePattern = "([0-9:\-\ ,]{23})" #First 23 characters of the log line
IPPattern = ".*;oip=([0-9.]+);"
accountPattern = "account=([^\;]*);"
protocolPattern = "protocol=(soap|imap|pop3)"

def parseDate(logLine):
    '''
    Given a log line returns a datetime object.
    '''
    dateResult = re.search(datePattern,logLine)
    if(dateResult):
        eventDateStr = dateResult.group(1)
        dateObject = datetime.datetime.strptime(eventDateStr,"%Y-%m-%d %H:%M:%S,%f")
        return dateObject
    else:
        return False
def parseIP(logLine):
    '''
    Given a log line returns event IP.
    '''
    IPResult = re.search(IPPattern,logLine)
    if (IPResult):
        IPResult=IPResult.group(1)
        return IPResult
    return False
def parseAccount(logline):
    '''
    Given a log line returns event account name.
    '''
    accountResult = re.search(accountPattern,logline)
    if (accountResult):
        accountResult = accountResult.group(1)
        return accountResult
    return False
def parseProtocol(logline):
    '''
    Given a log line returns event protocol.
    '''
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
    '''
    Return "success" if user logged in successfully, "fail" otherwise
    '''
    if "WARN" in logline:
        eventState = "fail"
    else:
        #Ignore zimbra inner account
        if "account=zimbra;" in logline:
            return
        successPattern = "protocol=(imap|pop3|soap);$"
        successResult = re.search(successPattern,logline)
        if (successResult):
            successResult = successResult.group(1)
            return "success"
        elif "account=zimbra;" in logline:
            return
        eventState=False
    return eventState      
def parseEventType(logline):
    '''
    Return true if this event regards user login.
    '''
    if "oip=" in logline:
        return True
    else:
        return False

def parseFailHandle(logline,parsedAccount,parsedIP,parsedDate):
    '''
    Handler for incorrect regex parsers.
    '''
    if type(parsedAccount) !=str:
        print(type(parsedAccount))
        log("ERROR:Account parse failed; "+logline,toPrint=config.printEvents)
        return False
    if type(parsedIP) !=str:
        log("ERROR:IP parse failed; "+logline,toPrint=config.printEvents)
        return False
    if type(parsedDate) !=datetime.datetime:
        log("ERROR:Date parse failed; "+logline,toPrint=config.printEvents)
        return False
    return True

def blockIP(ipaddr,blockedDate,account):
    '''
    Blocks a given IP address (adds to iptables)
    Adds the IP to a blocklist with a date
    Prints the name of account for which it was banned
    '''
    ipaddrTuple = checkBlock(ipaddr)
    if (ipaddrTuple):
        config.blockList.remove(ipaddrTuple)
    config.blockList.append((ipaddr,blockedDate))
    log("Blocked "+ipaddr+" for "+account,toPrint=config.printEvents)
    iptables.block(ipaddr)
    time.sleep(0.02)
    return True
def unblockIP(ipaddr):
    '''
    Removes an IP from blocklist and removes its rule from iptables.
    '''
    ipaddrTuple = checkBlock(ipaddr)
    if(ipaddrTuple):
        config.blockList.remove(ipaddrTuple)
        log("Unblocked "+ipaddr,toPrint=config.printEvents)
        return True
    else:
        print("IP not in blocklist",ipaddr)
        return False
    iptables.unblock(ipaddr)
    time.sleep(0.02)
    return True
def checkBlock(ipaddr):
    '''
    Checks if a given IP address is in a blocked state.
    Returns a tuple of form (str(ipaddr), datetime(blockedDate)).
    '''
    for blockedIP in config.blockList:
        if blockedIP[0] ==ipaddr:
            return blockedIP
    return False
    #Iptables..
def checkRecentFailList():
    '''
    Check if resetFailInterval expired for recentFailList.
    '''
    if len (recentFailList) == 0:
        return False
    for account in recentFailList:
        eventTuple = account[1]
        if (datetime.datetime.now() >= (eventTuple[1])+datetime.timedelta(minutes= config.resetFailInterval)):
            account.remove(eventTuple)
            #log("Cleaned: "+account[0],toPrint=True)
            if len(account) == 1 :
                recentFailList.remove(account)
    return True
def log(inputString,toPrint=False):
    '''
    Function to write into a log file (about parser's events).
    '''
    if '\n' not in inputString:
        inputString+='\n'

    currentTime = datetime.datetime.now()
    currentTime = currentTime.strftime('%Y-%m-%d %H:%M:%S.%f')
    tail = currentTime[-7:]
    roundedFloat = round(float(tail), 3)    
    string =str(roundedFloat)
    string = string[1:]
    while len(string) < 4:
        string+='0'
    currentTime = currentTime[:-7]
    currentTime = currentTime+string
    if toPrint:
        print(inputString)
    with open(config.outputLogFilePath,'a') as parserLog:
        parserLog.write(currentTime+' '+inputString)

class BackgroundBlockCheck(object):
    def __init__(self, interval=1):
        self.interval = interval
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()
    def run(self):
        while True:
            #If its time to unblock IP. unblock it
            for blocked in config.blockList:
                if (datetime.datetime.now() < (blocked[1])+datetime.timedelta(minutes= config.blockInterval)):
                    #Block time hasn't expired
                    #print("Still blocked..")
                    pass
                else:
                    #Block time expired
                    unblockIP(blocked[0])
            checkRecentFailList()
            time.sleep(self.interval)
config = config() #Load script configuration
iptables = iptables(config.iptablesChain)
logread = logread()
logread.init(config.logreadFilename)
recentFailList = []
checker = BackgroundBlockCheck(interval = config.checkInterval) #Start background thread
log("Launch")
def eventListOp(parsedIP,parsedAccount,parsedDate):    
    '''
    Adds an IP to recentEventList upon failure to login. Checks if multiple (recentFailCount) IPs access same account.
    '''
    if len (recentFailList) == 0:
        recentFailList.append([parsedAccount,(parsedIP,parsedDate)])
        return
    for account in recentFailList :
        if parsedAccount == account[0]:
            account.append((parsedIP,parsedDate))
            #checkRecentFailList()
            if len(account) >= config.recentFailCount+1:
                #if others in faillist arent blocked -> block them
                for event in account[1:]:
                    if not checkBlock(event[0]): #event[0] is an IP; event[1] the date when a login fail occured
                        blockIP(event[0],event[1],parsedAccount)
    else:
        recentFailList.append([parsedAccount,(parsedIP,parsedDate)])

def eventSuccessOp():
    #implement AbuseIPDB checks
    pass

def parseLine(line):
    if(parseEventType(line)):
        parsedState = parseEventState(line)
        if(parsedState=="fail"):
            parsedDate = (parseDate(line))
            if(parsedDate > (datetime.datetime.today() - datetime.timedelta(days=30))):
                #If the date in the event is within a 30 day timeframe from today...
                pass
            parsedIP = parseIP(line)
            if (parsedIP in config.whitelist) or (parsedIP in config.recentSuccessList):
                return
            parsedAccount = parseAccount(line)
            #parsedProtocol = parseProtocol(line)
            if not parseFailHandle(line,parsedAccount,parsedIP,parsedDate):
                return False
            if not checkBlock(parsedIP):#Ignore line if the IP is already blocked
                log ("Failed "+parsedIP+" for "+parsedAccount,toPrint=config.printEvents)
                eventListOp(parsedIP,parsedAccount,parsedDate)
        elif parsedState =="success":
            eventSuccessOp()
        else:
            log(line,toPrint=config.printEvents)
            log(parsedState,toPrint=config.printEvents)
            log("ERROR: eventType parse failed",toPrint=config.printEvents)
            exit()
    return True
def graceful_exit():
    global logread
    global iptables
    global checker
    del iptables
    del logread
    del checker
    exit()
def signal_handler(signal, frame):
    graceful_exit()
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

done=False #Change value to True, when initially finished reading from log file.
while True:
    if done:
        line = (logread.readLog())        
        if not line:
            log("Log file rotated",toPrint=True)
            logread.init(config.logreadFilename)
            line=logread.readLog()
        parseLine(line)
    else:
        with open(config.logreadFilename,encoding="utf8") as logfile:
            for line in logfile:
                parseLine(line.split('\n')[0])
            done=True
            log("Initial log read completed",toPrint=config.printEvents)
            print ("Blocklist: ", config.blockList)
#TODO:
    #Add functionality for email notification.
    #Improve parsers.