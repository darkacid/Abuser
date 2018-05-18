#!/usr/bin/env python3

import time
import os
class logread:
    def setFilename(self,logreadFilename):
        self.logreadFilename = logreadFilename
    def init(self,logreadFilename=None):    
        try :
            logreadFilename
        except:
            print ("Logreader filename not set!")
            exit()
        self.setFilename(logreadFilename)
        statinfo = os.stat(logreadFilename)
        self.startSize = statinfo.st_size
    def follow(self,thefile):
        thefile.seek(0,2)
        while True:     
            if self.startSize > os.stat(self.logreadFilename).st_size:
                return None
            line = thefile.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

    def readLog(self):    
        logfile = open(self.logreadFilename,"r",encoding="utf8")
        loglines = self.follow(logfile)
        for line in loglines:
            return (line.split('\n')[0])