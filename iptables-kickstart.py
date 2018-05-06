#!/usr/bin/env python3
from iptables import iptables
from config import config


iptables = iptables(config.iptablesChain)
print(iptables.block("200.201.202.201")) #Returns True, if successful
print(iptables.block("200.201.202.202"))
print(iptables.block("200.201.202.203"))
print(iptables.unblock("200.201.202.202"))
print(iptables.show())
print("Test")
