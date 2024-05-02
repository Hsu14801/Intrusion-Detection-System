from threading import Thread
from scapy.all import *
import logging
import SIDS.RuleRead
from SIDS.Rule import *

# from Anomaly import detect

class Sniff():
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList):
        self.ruleList = ruleList

    def inPacket(self, pkt):
        """Directive for each received packet."""
        print ("checking rule.....")
        for rule in self.ruleList:
            matched = rule.match(pkt)
            if (matched):
                print(rule.getMatchedPrintMessage(pkt))
                return True


