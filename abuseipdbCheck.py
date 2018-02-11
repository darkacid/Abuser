#!/usr/bin/env python3
'''
setApiKey(apiKey)
setPeriod(days)
checkIP(ip)
'''
import requests
import json
import sys
abuseIPDB_APIKEY = ""
abuseIPDB_days = "60"

def setApiKey(apiKey):
    '''Sets API key variable given by abuseIPDB'''
    abuseIPDB_APIKEY = apiKey

def setPeriod(days):
    '''Sets day variable to check the reports in the last X days.'''
    abuseIPDB_days = str(days)

def checkIP(ip):
    '''
    Returns a list in the form [abuseCount, country]
    Given IP, API Key and period of time in days.
    Returns [0, "No abuse"], since the API doesn't show country when no abuse is reported.

     
    '''
    apiRequestURL = "https://www.abuseipdb.com/check/"+ip+"/json?key="+abuseIPDB_APIKEY+"&days="+abuseIPDB_days
    session_requests = requests.session()    
    try:
        apiResult = session_requests.get(apiRequestURL, timeout = 5)       
        #Result is either {} if 1 occurence, [] if 0 occurence, [{},{},...]  if multiple occurences (a list of dicts) .
    except:
        return "Error occured"   
    data = json.loads(apiResult.text)

    if type(data) == dict:
        country = data["country"]
        abuseCount = 1
        return [abuseCount,country]
    elif type(data) == list:
        abuseCount = len(data)
        if(abuseCount):
            return [abuseCount,data[0]["country"]]
        else:
            #Returns "No abuse" because API doesn't respond with a country.
            return [abuseCount,"No abuse"]
    return "Error occured"
if __name__ == "__main__":
    if  len(sys.argv) == 2:
        print(checkIP(str(sys.argv[1])))