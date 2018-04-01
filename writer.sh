#!/usr/bin/env bash
#Script to test and debug the audit parser
#Writes a test line every second 
while true; do
  echo "2018-04-01 16:04:25,145 WARN  [Pop3SSLServer-400] [ip=1.1.1.1;oip=1.9.9.9;] security - cmd=Auth; account=admin@domain.tek; protocol=pop3; error=authentication failed for [admin@domain.tek], invalid password;"
  sleep 1
done >> auditer.log
