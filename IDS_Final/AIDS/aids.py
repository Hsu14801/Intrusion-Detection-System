from AIDS.flow import Flow
from AIDS.packet import packetDetails

from sklearn.preprocessing  import LabelEncoder

from random import random
from time import sleep
from threading import Thread, Event
from scapy.sendrecv import sniff


import numpy as np
import pickle
import csv 
import traceback

import json
import pandas as pd
import warnings

from threading import Thread
from scapy.all import *


class anomaly(Thread):
    
    def __init__(self, ruleList):

        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList

        self.current_flows = {}
        self.FlowTimeout = 600
        self.stopped = False
        # with open('AIDS\\Model\\model.pkl', 'rb') as f:
        with open('AIDS\\test.pkl', 'rb') as f:
            self.model = pickle.load(f)
        warnings.filterwarnings("ignore", message="Trying to unpickle estimator SimpleImputer from version 1.4.1.post1 when using version 1.3.0.") 
        # f = open('test.txt','w') 
               

    def newPacket(self, p):
        try:
            data = []
            packet = packetDetails()
            # p.show()
            packet.setDest(p)
            # print(packet.getDest())
            packet.setSrc(p)
            # print("Source: ",packet.getSrc())
            packet.setSrcPort(p)
            # print(packet.getSrcPort())
            packet.setDestPort(p)
            # print(packet.getDestPort())
            packet.setProtocol(p)
            # print(packet.getProtocol())
            packet.setTimestamp(p)
            # print(packet.getTimestamp())
            packet.setFlag(p)
            packet.setPayloadBytes(p)
            packet.setHeaderBytes(p)
            packet.setPacketSize(p)
            packet.setWinBytes(p)
            # packet.setMss(p)
            packet.setID(p)
            # print(packet.getFwdID())
            # print(packet.getBwdID())
            # print(packet.getSYNFlag())
            # print("current flows", self.current_flows)
            if packet.getFwdID() in self.current_flows.keys():
                flow = self.current_flows[packet.getFwdID()]
                # print(flow)
                # check for timeout
                # for some reason they only do it if packet count > 1
                if (packet.getTimestamp() - flow.getFlowLastSeen()) > self.FlowTimeout:
                    data = flow.terminated()
                    del self.current_flows[packet.getFwdID()]
                    flow = Flow(packet)
                    self.current_flows[packet.getFwdID()] = flow

                # check for fin flag
                elif packet.getFINFlag() or packet.getRSTFlag():
                    flow.new(packet, 'fwd')
                    data = flow.terminated()
                    del self.current_flows[packet.getFwdID()]
                    del flow

                else:
                    flow.new(packet, 'fwd')
                    self.current_flows[packet.getFwdID()] = flow
                    data = flow.terminated()

            elif packet.getBwdID() in self.current_flows.keys():
                flow = self.current_flows[packet.getBwdID()]

                # check for timeout
                if (packet.getTimestamp() - flow.getFlowLastSeen()) > self.FlowTimeout:
                    data = flow.terminated()
                    del self.current_flows[packet.getBwdID()]
                    del flow
                    flow = Flow(packet)
                    self.current_flows[packet.getFwdID()] = flow

                elif packet.getFINFlag() or packet.getRSTFlag():
                    flow.new(packet, 'bwd')
                    data = flow.terminated
                    del self.current_flows[packet.getBwdID()]
                    del flow
                else:
                    flow.new(packet, 'bwd')
                    self.current_flows[packet.getBwdID()] = flow
                    data = flow.terminated()
            else:

                flow = Flow(packet)
                # flow.new(packet, 'fwd')
                # flow.new(packet, 'bwd')
                # print("time : ",packet.getTimestamp())
                self.current_flows[packet.getFwdID()] = flow
                # print(flow.terminated())
            
                # current_flows[packet.getBwdID()] = flo
                # print(current_flows)
                # current flows put id, (new) flow
            # print(self.current_flows)
            if data:
                # print("Destination Port", data[0])
                
                # df = pd.DataFrame(test)
                # print(df)
                # data = [np.nan if x in [np.inf, -np.inf] else x for x in data[:78]]
                print([data])
                if np.nan in data:
                    return None

                else:
                    test = [data]
                df2 = pd.read_csv('AIDS\\data\\testing.csv')
                df = pd.DataFrame(test, columns = df2.columns)
                
                y = self.model.predict(df)
                prob = self.model.predict_proba(df)

                # Flatten the 2D array into a 1D array
                y = np.array(y)
                y = y.flatten()

                print('Result ->',y[0])
                print("Proba ->",prob,"\n\n")

                f = open('AIDS\\test.txt','a')    

                if y != 'BENIGN':
                    rules = "alert "+str(packet.getProtocol()).lower()+" "+str(packet.getSrc())+" "+str(packet.getSrcPort())+" -> "+str(packet.getDest())+" "+str(packet.getDestPort())+" (msg: \"Possible "+str(y)+"; len: "+str(packet.getHeaderBytes())+"; tos: "+str(packet.getTos())+"; offset: "+str(packet.getOffset())+";\")\n"
                    f.writelines(rules)


        except AttributeError:
            # not IP or TCP
            # print("not IP or TCP")
            return None

        except:
            traceback.print_exc()
    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped
        

    def inPacket(self, pkt):
        """Directive for each received packet."""
        print ("checking rule.....")
        # pkt.show()
        # print(str(pkt[ARP].op))
        for rule in self.ruleList:
            # Check all rules
            matched = rule.match(pkt)
            if (matched):
                # logMessage = rule.getMatchedMessage(pkt)
                # logging.warning(logMessage)
                print (rule.getMatchedPrintMessage(pkt))

            else:
                # aids = anomaly()
                self.newPacket(pkt)

    def run(self):
        print ("Sniffing started....\nPress 'Esc' to quit the program\n-------------------------------------------------------------\n\n")
        sniff(prn=self.inPacket, filter="arp", store=0, stop_filter=self.stopfilter)

    # def sniff_and_detect(self):

    #     # while 1:
    #     print("Begin Sniffing....")
    #         # sniff(iface="en0", prn=newPacket)
    #     sniff(prn=self.newPacket, filter = "",count = 100)

# a = aids()
# a.sniff_and_detect()


# if p is not None:
#     for dport in p[0]:
#         Destination_port.append(dport) 
#     Duration.append(p[1])  
# df_dict = {, 'Duration' : Duration} 
# print(df_dict)