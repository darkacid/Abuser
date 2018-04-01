#!/usr/bin/env python3
'''
Inf dev...
'''
import re
import datetime
import threading
import time
import os

import logread
# Pattern definitions
datePattern = "([0-9:\-\ ,]{23})" #First 23 characters of the log line
IPPattern = ".*;oip=([0-9.]+);"
accountPattern = "account=([\w\.\@]+);"
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
        return "success"
    #if "invalid password" in logline:
    #    eventState = "invalid password"
    return eventState      
def parseEventType(logline):
    '''
    Return true if this event regards user login.
    '''
    if "oip=" in logline:
        return True
    else:
        return False

def blockIP(ipaddr,blockedDate):
    for blockedIP in config.blockList:
        if blockedIP[0] == ipaddr:
            config.blockList.remove(blockedIP)
    config.blockList.append((ipaddr,blockedDate))
    log("Blocked "+ipaddr,toPrint=config.printEvents)
    #"iptables ...."
    return True
def unblockIP(ipaddr):
    for blockedIP in config.blockList:
        if blockedIP[0] == ipaddr:
            config.blockList.remove(blockedIP)
        else:
            print("IP not in blocklist",ipaddr)
            return False
    log("Unblocked "+ipaddr,toPrint=config.printEvents)
    #Iptables..
    return True
def checkBlock(ipaddr):
    '''
    Checks if a given IP address is in a blocked state.
    '''
    for blockedIP in config.blockList:
        if blockedIP[0] ==ipaddr:
            return True
    return False
    #Iptables..
def checkRecentFailList(ipaddr):
    '''
    Check if resetFailInterval expired for an IP in recentFailList.
    '''
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

class config:
    def readConfigFile(self):
        pass
    def __init__(self):
        self.readConfigFile()
        log("Launch")

    '''
    Config file default values
    '''

    whitelist=[] #List of IPs not to be blocked at all.
    recentSuccessList = [] #List of IPs that recently logged in successfully.
    blockList = [] #List of currently blocked IPs.

    #Background check if block time has expired.
    checkInterval = 1 #Seconds

    #If an IP fail to login to an account within this time period from one another -> block IP.
    recentFailInterval = 15 #Minutes

    #Once a recent fail is registered, it will be unregistered after this time period.
    resetFailInterval = 60 #Minutes

    #$$$ (Amount of times it takes to fail login for subsequent fail IPs to be blocked)If multiple IPs fail to login to an account 
    recentFailCount = 3 #Times

    #If an IP successfully logged in to an account add this IP to "recentSuccessList" for "recentLoginInterval" minutes.
    recentLoginInterval = 5 #Minutes

    #If an IP is blocked, unblock  "blockInterval" minutes later.
    blockInterval = 5 #Minutes

    #Once an IP has successfully logged in, add it to recentSuccessList for this many minutes.
    immuneTime = 3600 #Minutes

    #Path to the log file where parser's output is written
    outputLogFilePath = "auditParse.log"

    #Path to parser's config file
    parserConfigFilePath = "parser.config"
    
    #Name of the iptables chain where the blocking action will occur
    iptablesChain = "auditParser" #Name of the iptables chain name
    
    #Whether or not to print events to the console once they are logged to parser's log file.
    printEvents = True #Prints output log events to console


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
            time.sleep(self.interval)
config() #Load script configuration
recentFailList = []
checker = BackgroundBlockCheck(interval = config.checkInterval) #Start background thread
def eventListOp(parsedIP,parsedAccount,parsedDate):    
    '''
    Adds an IP to recentEventList upon failure to login. Checks if multiple (recentFailCount) IPs access same account.
    '''
    for account in recentFailList :
        if parsedAccount == account[0]:
            account.append((parsedIP,parsedDate))
            #checkRecentFailList()
            if len(account) >= config.recentFailCount+1:
                #if others in faillist arent blocked -> block them
                for event in account[1:]:
                    if not checkBlock(event[0]): #event[0] is an IP; event[1] the date when a login fail occured
                        blockIP(event[0],event[1])
            '''
            #If the fail event took place within recentFailInterval then block the ip
            if (datetime.datetime.now() < (account[-1][1])+datetime.timedelta(minutes=config.recentFailInterval)):
                blockIP(parsedIP,parsedDate)
                account.append((parsedIP,parsedDate))
            else:
                account.append((parsedIP,parsedDate))
            return
            '''
        else:
            recentFailList.append([parsedAccount,(parsedIP,parsedDate)])
    #print(recentFailList)

def parseLine(line):
    if(parseEventType(line)):
        parsedDate = (parseDate(line))
        if(parsedDate > (datetime.datetime.today() - datetime.timedelta(days=30))):
            #If the date in the event is within a 30 day timeframe from today...
            pass
        #parsedDate
        parsedIP = parseIP(line)
        if (parsedIP in config.whitelist) or (parsedIP in config.recentSuccessList):
            return
        parsedAccount = parseAccount(line)
        parsedProtocol = parseProtocol(line)
        parsedState = parseEventState(line)
        if(parsedState=="fail"):
            eventListOp(parsedIP,parsedAccount,parsedDate)
        #if parsedState == "fail":
        #    eventListOp(parsedIP,parsedAccount,datetime.datetime.today())
        #print(parsedDate,parsedIP,parsedAccount,parsedProtocol,parsedState)
        #print(line)

#Testing the blockIP function
#blockIP("1.1.1.1",datetime.datetime.now())

logread.filename = "auditer.log"

done=False #Change value to True, when initially finished reading from log file.
while True:
    if done:
        line = (logread.readLog())
        parseLine(line)
    else:
        with open(logread.filename,encoding="utf8") as logfile:
            for line in logfile:
                parseLine(line.split('\n')[0])
            done=True
            print("Initial log read completed")
            print (config.blockList)
#TODO:
    #Rename eventList to recentFailList
    #$$$ Write proper comments.