#!/usr/bin/env python3
'''
Inf dev...
'''
import re
import datetime
import threading
import time
import os
import json

import logread
import abuseipdbCheck
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
    #"iptables ...."
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
    #Iptables..
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

class config:
    def readConfigFile(self):        
        if os.path.exists(self.parserConfigFilePath):
            with open(self.parserConfigFilePath, 'r') as f:
                configfile = json.load(f)
                if(configfile["whitelist"]):
                    print(type(configfile["whitelist"]))
                    self.whitelist+= configfile["whitelist"]
        else:
            configfile = {"whitelist": [], 'key2': 'value2'}
            with open(self.parserConfigFilePath, 'w') as f:
                json.dump(configfile, f)
    def __importJson(self):
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

    #Background check whether block time has expired.
    checkInterval = 1 #Seconds

    #If an IP fail to login to an account within this time period from one another -> block IP.
    #recentFailInterval = 15 #Minutes

    #Once a recent fail is registered, it will be unregistered after this time period.
    resetFailInterval = 60 #Minutes

    #$$$ (Amount of times it takes to fail login for subsequent fail IPs to be blocked)If multiple IPs fail to login to an account 
    recentFailCount = 3 #Times

    #If an IP successfully logged in to an account add this IP to "recentSuccessList" for "recentLoginInterval" minutes.
    #recentLoginInterval = 5 #Minutes

    #If an IP is blocked, unblock  "blockInterval" minutes later.
    blockInterval = 5 #Minutes

    #Once an IP has successfully logged in, add it to recentSuccessList for this many minutes.
    immuneTime = 3600 #Minutes

    #Path to the log file where parser's output is written
    outputLogFilePath = "auditParse.log"

    #Path to parser's config file
    parserConfigFilePath = "parser.conf"
    
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
            checkRecentFailList()
            time.sleep(self.interval)
config() #Load script configuration
recentFailList = []
checker = BackgroundBlockCheck(interval = config.checkInterval) #Start background thread
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
                        return
    else:
        recentFailList.append([parsedAccount,(parsedIP,parsedDate)])

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
                eventListOp(parsedIP,parsedAccount,parsedDate)
            #if parsedState == "fail":
            #    eventListOp(parsedIP,parsedAccount,datetime.datetime.today())
            #print(parsedDate,parsedIP,parsedAccount,parsedProtocol,parsedState)
            #print(line)
    return True

#Testing the blockIP function
#blockIP("1.1.1.1",datetime.datetime.now(),"admin@domain.tek")

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
            log("Initial log read completed",toPrint=config.printEvents)
            print ("Blocklist: ", config.blockList)
#TODO:
    #Improve config file reader function.