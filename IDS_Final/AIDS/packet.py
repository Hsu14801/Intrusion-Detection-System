from scapy.all import *
import psutil

# flags = {
#     'F' : 'FIN',
#     'S' : 'SYN',
#     'R' : 'RST',
#     'P' : 'PSH',
#     'A' : 'ACK',
#     'U' : 'URG',
#     'E' : 'ECE',
#     'C' : 'CWR',
#     'N' : ''
# }

class packetDetails:
    def __init__(self):
        self.src = ""
        self.dest = ""
        self.src_port = 0
        self.dest_port = 0
        self.protocol = ''
        self.timestamp = 0

        self.PSH_flag = False
        self.FIN_flag = False
        self.SYN_flag = False
        self.ACK_flag = False
        self.URG_flag = False
        self.RST_flag = False
        self.CWE_flag = False
        self.ECE_flag = False

        self.payload_bytes = 0
        self.header_bytes = 0
        self.packet_size = 0
        self.win_bytes = 0
        self.mss = 0
        self.tos = 0
        self.offset = 0

        self.fwd_id = ""
        self.bwd_id = ""

        self.pid = None
        self.p_name = ''

    def setSrc(self, pkt):
        if ARP in pkt:
            self.src = pkt.getlayer(ARP).psrc
        if IP in pkt:
            self.src = pkt.getlayer(IP).src
        if IPv6 in pkt:
            self.src = pkt.getlayer(IPv6).src

    def getSrc(self):
        return self.src

    def setDest(self, pkt):
        if ARP in pkt:
            self.dest = pkt.getlayer(ARP).pdst
        if IP in pkt:
            self.dest = pkt.getlayer(IP).dst
        if IPv6 in pkt:
            self.dest = pkt.getlayer(IPv6).dst

    def getDest(self):
        return self.dest

    def setSrcPort(self, pkt):

        if pkt.haslayer(TCP):
            self.src_port = pkt.getlayer(TCP).sport
        
        elif pkt.haslayer(UDP):
            self.src_port = pkt.getlayer(UDP).sport

        else:
            self.src_port = 0

        if self.pid is None and self.p_name == '':
            connections = psutil.net_connections()

            for con in connections:
                if(con.laddr.port -  self.src_port == 0.0) or (con.laddr.port - self.dest_port == 0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

    
    def getSrcPort(self):
        return self.src_port
    
    def setDestPort(self, pkt):

        if pkt.haslayer(TCP):
            self.dest_port = pkt.getlayer(TCP).dport

        elif pkt.haslayer(UDP):
            self.dest_port = pkt.getlayer(UDP).dport

        else:
            self.dest_port = 0
        
        if self.pid  is None and self.p_name == '':
            connections = psutil.net_connections()
            for con in connections:
                if(con.laddr.port - self.src_port == 0.0) or (con.laddr.port - self.dest_port == 0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

    def getPID(self):
        return self.pid

    def getPName(self):
        return self.p_name

    def getDestPort(self):
        return self.dest_port

    def setProtocol(self, pkt):

        if pkt.haslayer(TCP):
            self.protocol = 'TCP'

        if pkt.haslayer(UDP):
            self.protocol = 'UDP'

        if pkt.haslayer(ICMP):
            self.protocol = 'ICMP'

        if pkt.haslayer(ARP):
            self.protocol = 'ARP'

        if pkt.haslayer(IPv6):
            self.protocol = 'IPv6'

        if pkt.haslayer(IP) and not (pkt.haslayer('TCP') or pkt.haslayer('UDP')) :
            self.protocol = 'Routing'

    def getProtocol(self):
        return self.protocol

    def setTimestamp(self, pkt):
        self.timestamp = pkt.time
    
    def getTimestamp(self):
        return self.timestamp

    def setFlag(self, pkt):
        if pkt.haslayer(TCP):
            self.tcp_flags = []
            self.tcp_flags.append(pkt[TCP].flags)
            # print("Flags:",self.tcp_flags)
            for flag in self.tcp_flags:
                if 'P' in flag:
                    self.PSH_flag = True
                if 'F' in flag:
                    self.FIN_flag = True
                if 'S' in flag:
                    self.SYN_flag = True
                if 'A' in flag:
                    self.ACK_flag = True
                if 'U' in flag:
                    self.URG_flag = True
                if 'R' in flag:
                    self.RST_flag = True
                if 'C' in flag:
                    self.CWE_flag = True
                if 'E' in flag:
                    self.ECE_flag = True

    def getPSHFlag(self):
        return self.PSH_flag   
    
    def getFINFlag(self):
        return self.FIN_flag

    def getSYNFlag(self):
        return self.SYN_flag
            
    def getRSTFlag(self):
        return self.RST_flag

    def getACKFlag(self):
        return self.ACK_flag

    def getURGFlag(self):
        return self.URG_flag

    def getCWEFlag(self):
        return self.CWE_flag
    
    def getECEFlag(self):
        return self.ECE_flag

    def setPayloadBytes(self, pkt):
        if pkt.haslayer(TCP):
            self.payload_bytes = len(pkt[TCP].payload)
        if pkt.haslayer(UDP):
            self.payload_bytes = len(pkt[UDP].payload)

    def getPayloadBytes(self):
        return self.payload_bytes

    def setHeaderBytes(self, pkt):
        if pkt.haslayer(TCP):
            self.header_bytes = len(pkt[TCP]) - len(pkt[TCP].payload)
        if pkt.haslayer(UDP):
            self.header_bytes = len(pkt[UDP]) - len(pkt[UDP].payload)

    def getHeaderBytes(self):
        return self.header_bytes

    def setPacketSize(self, pkt):
        if pkt.haslayer(TCP):
            self.packet_size = len(pkt[TCP])
        if pkt.haslayer(UDP):
            self.packet_size = len(pkt[UDP])

    def getPacketSize(self):
        return self.packet_size

    def setWinBytes(self, pkt):
        if pkt.haslayer(TCP):
            self.win_bytes = pkt[0].window

    def getWinBytes(self):
        return self.win_bytes

    # def getMss(self):
    #     return self.mss

    # def setMss(self, pkt):
    #     if pkt.haslayer(TCP):
    #         for option_kind, option_data in pkt[TCP].options:
    #             if option_kind == 'MSS':
    #                 self.mss = option_data
    def getTos(self):
        return self.tos

    def setTos(self, pkt):
        if pkt.haslayer(IP):
            self.tos = int(pkt[IP].tos)
    
    def getOffset(self):
        return self.offset

    def setOffset(self, pkt):
        if pkt.haslayer(IP):
            self.offset = int(pkt[IP].frag)

    def setID(self, pkt):
        self.fwd_id = self.src + "-" + self.dest + "-" + \
                        str(self.src_port) + "-" + str(self.dest_port) + "-" + self.protocol

        self.bwd_id = self.dest + "-" + self.src + "-" + \
                        str(self.dest_port) + "-" + str(self.src_port) + "-" + self.protocol

    def getFwdID(self):
        return self.fwd_id

    def getBwdID(self):
        return self.bwd_id 
# pkt = packetDetails()
# sniff(prn = pkt.setProtocol, count=1)
# print(pkt.getProtocol())
    
