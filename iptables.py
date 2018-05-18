#!/usr/bin/env python3
'''
Module for handling iptables requests
'''
import subprocess
import os
import sys
import re
class   iptables:
    def failHandle(self,proc_call,call_output):
        '''
        Catches errors by the iptables subprocess calls.
        '''
        if "xtables lock. " in call_output[1].decode():
            return False

        if (proc_call.returncode !=0):
            self.moduleOutput(call_output[0].decode()+call_output[1].decode())
        return True
    def moduleOutput(self,message):
        '''
        Returns error messages to parent module
        '''
        message="IPTables# " + message
        raise Exception(message)
    def __init__(self,iptablesChain):
        self.checkRoot()
        self.iptablesChain = iptablesChain
        self.createChain()
    def __del__(self):
        self.checkRoot()
        self.delChain()
    def checkRoot(self):
        if not (os.getuid() == 0):
           self.moduleOutput("Not executed as root")
    def createChain(self):
        '''
        Creates the IPtables chain.
        '''
        self.iptablesExecute("iptables -N " + self.iptablesChain)
    def delChain(self):
        '''
        Flushes and Deletes the IPtables chain.
        '''
        self.iptablesExecute("iptables -F " + self.iptablesChain)
        self.iptablesExecute("iptables -X " + self.iptablesChain)
    
    def show(self):
        '''
        Returns a list of blocked IPs from IPTables.
        '''
        executeString = self.iptablesExecute("iptables -S " +self.iptablesChain +"|awk '{print $4}'|grep \\32")[0].decode()
        executeList = executeString.split('\n')
        for line in executeList:
            if not (re.match("[0-9\.]+",line)):
                executeList.remove(line)
        return executeList
    def chainAction(self,ipaddr,action=None):
        '''
        Executes main actions; Possible actions: block, unblock
        Returns True upon completion.
        '''
        if not action:
            self.moduleOutput("No Action specified during iptables call")
        if not ipaddr:
            self.moduleOutput("No IPaddr specified during iptables call")

        actionstring = self.iptablesChain + " -s " + ipaddr+" -j DROP"
        if action == "block":
            actionstring = "iptables -A" + actionstring
        elif action == "unblock":
            actionstring = "iptables -D" + actionstring
        else:
            self.moduleOutput ("Wrong Action specified during iptables call")
        self.iptablesExecute(actionstring)
        return(True)
    def iptablesExecute(self,actionstring):
        '''
        Makes the main call to subprocess.
        '''
        proc_call = subprocess.Popen(actionstring, stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        output = proc_call.communicate()
        if not self.failHandle(proc_call,output):
            self.iptablesExecute(actionstring)
        return output
    def block(self,ipaddr):
        ipaddr+="/32"
        return (self.chainAction(ipaddr,action="block"))
    def unblock(self,ipaddr):
        ipaddr+="/32"
        return (self.chainAction(ipaddr,action="unblock"))
