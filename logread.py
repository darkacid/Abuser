#!/usr/bin/env python3

import time
import os
import config

try :
    filename = config.logreadFilename
except:
    print ("Logreader filename cannot be set!")
    exit()
statinfo = os.stat(filename)
startSize = statinfo.st_size
def follow(thefile):
    thefile.seek(0,2)
    while True:
        if startSize > os.stat(filename).st_size:
            print ("file rotated")
            exit()
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def readLog():    
    logfile = open(filename,"r",encoding="utf8")
    loglines = follow(logfile)
    for line in loglines:
        return (line.split('\n')[0])