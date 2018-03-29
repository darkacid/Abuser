#!/usr/bin/env python3

import time
import os

try :
    filename
except:
    filename = "auditer.log"
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
    logfile = open(filename,"r")
    loglines = follow(logfile)
    for line in loglines:
        return (line.split('\n')[0])