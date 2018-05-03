#!/usr/bin/env python3
'''
Module for handling iptables requests
'''
import subprocess
import os

def init():
    if not (os.getuid() == 0):
        return ("IPtables not executed as root", False)
def execute():

    proc_call = subprocess.Popen('iptables', stdout=subprocess.PIPE,shell=True)
    output = proc_call.communicate()
    if (proc_call.returncode == 2):
        return ("ERROR: IPtables"+output[0].decode(), False)