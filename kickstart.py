#!/usr/bin/env python3
import  abuseipdbCheck

abuse = abuseipdbCheck.checkIP("82.223.81.89")
print ("Abuse reports from this IP:", abuse[0])
print("Country of IP:", abuse[1])