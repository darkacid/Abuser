import os
import json
class config:
    def readConfigFile(self):
        if os.path.exists(self.parserConfigFilePath):
            with open(self.parserConfigFilePath, 'r') as f:
                configfile = json.load(f)
                if(configfile["whitelist"]):
                    self.whitelist+= configfile["whitelist"]
                if(configfile["blockList"]):
                    self.blockList = configfile["blockList"]
                if(configfile["checkInterval"]):
                    self.checkInterval = configfile["checkInterval"]
                if(configfile["resetFailInterval"]):
                    self.resetFailInterval = configfile["resetFailInterval"]
                if(configfile["recentFailCount"]):
                    self.recentFailCount = configfile["recentFailCount"]
                if(configfile["blockInterval"]):
                    self.blockInterval = configfile["blockInterval"]
                if(configfile["immuneTime"]):
                    self.immuneTime = configfile["immuneTime"]
                if(configfile["outputLogFilePath"]):
                    self.outputLogFilePath = configfile["outputLogFilePath"]
                if(configfile["logreadFilename"]):
                    self.logreadFilename = configfile["logreadFilename"]
                if(configfile["iptablesChain"]):
                    self.iptablesChain = configfile["iptablesChain"]
                if(configfile["printEvents"]):
                    self.printEvents = configfile["printEvents"]                
        else:
            configfile ={
            "whitelist": [], 'checkInterval': '','blockList' : '','checkInterval': '',
            'resetFailInterval': '','recentFailCount':'','blockInterval':'','immuneTime':'',
            'outputLogFilePath': '','logreadFilename':'','iptablesChain':'','printEvents':''}
            with open(self.parserConfigFilePath, 'w') as f:
                json.dump(configfile, f)
    def __importJson(self):
        pass
    def __init__(self):
        self.readConfigFile()

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
    
    #Path to the audit log file
    logreadFilename = "audit.log"

    #Path to parser's config file
    parserConfigFilePath = "parser.conf"
    
    #Name of the iptables chain where the blocking action will occur
    iptablesChain = "auditParser" #Name of the iptables chain name
    
    #Whether or not to print events to the console once they are logged to parser's log file.
    printEvents = True #Prints output log events to console