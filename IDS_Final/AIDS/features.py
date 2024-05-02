# from packet import packetDetails
class features:
    def __init__(self):
        self.dest_port = 0
        self.flow_duration = 0
        self.total_fwd_packet = 1
        self.total_bwd_packet = 0
        self.total_length_of_fwd_packet = 0
        self.total_length_of_bwd_packet = 0

        self.flow_bytes_s = 0.000000
        self.flow_packet_s = 0.000000

        self.fwd_packets_s = 0.000000
        self.bwd_packets_s = 0.000000
        
        self.fwd_packet_len_max = 0
        self.fwd_packet_len_min = 0
        self.fwd_packet_len_mean = 0.000000
        self.fwd_packet_len_std = 0.000000

        self.bwd_packet_len_max = 0
        self.bwd_packet_len_min = 0
        self.bwd_packet_len_mean = 0.000000
        self.bwd_packet_len_std = 0.000000

        self.flow_IAT_mean = 0.000000
        self.flow_IAT_std = 0.000000
        self.flow_IAT_max = 0
        self.flow_IAT_min = 0
        
        self.fwd_IAT_total = 0
        self.fwd_IAT_mean = 0.000000
        self.fwd_IAT_std = 0.000000
        self.fwd_IAT_max = 0
        self.fwd_IAT_min = 0 

        self.bwd_IAT_total = 0
        self.bwd_IAT_mean = 0.000000
        self.bwd_IAT_std = 0.000000
        self.bwd_IAT_max = 0
        self.bwd_IAT_min = 0

        self.fwd_PSH_flags = 0
        self.bwd_PSH_flags = 0
        self.fwd_URG_flags = 0
        self.bwd_URG_flags = 0

        self.fwd_header_length = 0
        self.bwd_header_length = 0

        self.down_up_ratio = 0

        self.min_pack_length = 0
        self.max_pack_length = 0
        self.pack_len_mean = 0.000000
        self.pack_len_std = 0.000000
        self.pack_len_var = 0.000000
        
        self.FIN_flag_count = 0
        self.SYN_flag_count = 0
        self.RST_flag_count = 0
        self.PSH_flag_count = 0
        self.ACK_flag_count = 0
        self.URG_flag_count = 0
        self.CWE_flag_count = 0
        self.ECE_flag_count = 0

        self.avg_pack_size = 0.0
        self.avg_fwd_seg_size = 0.0
        self.avg_bwd_seg_size = 0.0

        self.fwd_avg_bytes_bulk = 0
        self.fwd_avg_packets_bulk = 0
        self.fwd_avg_bulk_rate = 0

        self.bwd_avg_bytes_bulk = 0
        self.bwd_avg_packets_bulk = 0
        self.bwd_avg_bulk_rate = 0

        self.init_win_bytes_fwd = -1
        self.init_win_bytes_bwd = -1

        self.act_data_pkt_fwd = 1
        self.min_seg_size_fwd = 0 

        self.active_mean = 0.000000
        self.active_std = 0.000000
        self.active_max = 0
        self.active_min = 0

        self.idle_mean = 0.000000
        self.idle_std = 0.000000
        self.idle_max = 0
        self.idle_min = 0

        self.src = ""
        self.dest = ""
        self.src_port = 0
        self.protocol = ''
        self.timestamp = 0

        self.pid = -1
        self.p_name = 'Not Found'

    def getDestPort(self):
        return self.dest_port

    def setDestPort(self, value):
        self.dest_port = value

    def getFlowDuration(self):
        return self.flow_duration

    def setFlowDuration(self, value):
        self.flow_duration = int(round(value))

    def getTotalFwdPacket(self):
        return self.total_fwd_packet
    
    def setTotalFwdPacket(self, value):
        self.total_fwd_packet = value

    def getTotalBwdPacket(self):
        return self.total_bwd_packet
    
    def setTotalBwdPacket(self, value):
        self.total_bwd_packet = value

    def getTotalLengthofFwdPacket(self):
        return self.total_length_of_fwd_packet
    
    def setTotalLengthofFwdPacket(self, value):
        self.total_length_of_fwd_packet = value
    
    def getTotalLengthofBwdPacket(self):
        return self.total_length_of_bwd_packet
    
    def setTotalLengthofBwdPacket(self, value):
        self.total_length_of_bwd_packet = value

    def getFlowBytes_s(self):
        return self.flow_bytes_s

    def setFlowBytes_s(self, value):
        self.flow_bytes_s = float(value)
    
    def getFlowPacket_s(self):
        return self.flow_packet_s

    def setFlowPacket_s(self, value):
        self.flow_packet_s = float(value)
    
    def getFwdPackets_s(self):
        return self.fwd_packets_s

    def setFwdPackets_s(self, value):
        self.fwd_packets_s = float(value)

    def getBwdPackets_s(self):
        return self.bwd_packets_s

    def setBwdPackets_s(self, value):
        self.bwd_packets_s = float(value)

    def getFwdPacketLenMax(self):
        return self.fwd_packet_len_max

    def setFwdPacketLenMax(self, value):
        self.fwd_packet_len_max = value

    def getFwdPacketLenMin(self):
        return self.fwd_packet_len_min

    def setFwdPacketLenMin(self, value):
        self.fwd_packet_len_min = value

    def getFwdPacketLenMean(self):
        return self.fwd_packet_len_mean

    def setFwdPacketLenMean(self, value):
        self.fwd_packet_len_mean = float(value)

    def getFwdPacketLenStd(self):
        return self.fwd_packet_len_std

    def setFwdPacketLenStd(self, value):
        self.fwd_packet_len_std = float(value)

    def getBwdPacketLenMax(self):
        return self.bwd_packet_len_max

    def setBwdPacketLenMax(self, value):
        self.bwd_packet_len_max = value

    def getBwdPacketLenMin(self):
        return self.bwd_packet_len_min

    def setBwdPacketLenMin(self, value):
        self.bwd_packet_len_min = value

    def getBwdPacketLenMean(self):
        return self.bwd_packet_len_mean

    def setBwdPacketLenMean(self, value):
        self.bwd_packet_len_mean = float(value)

    def getBwdPacketLenStd(self):
        return self.bwd_packet_len_std

    def setBwdPacketLenStd(self, value):
        self.bwd_packet_len_std = float(value)

    def getFlowIATMean(self):
        return self.flow_IAT_mean

    def setFlowIATMean(self, value):
        self.flow_IAT_mean = float(value)

    def getFlowIATStd(self):
        return self.flow_IAT_std

    def setFlowIATStd(self, value):
        self.flow_IAT_std= float(value)

    def getFlowIATMax(self):
        return self.flow_IAT_max

    def setFlowIATMax(self, value):
        self.flow_IAT_max = int(round(value))

    def getFlowIATMin(self):
        return self.flow_IAT_min

    def setFlowIATMin(self, value):
        self.flow_IAT_min = int(round(value))

    def getFwdIATTotal(self):
        return self.fwd_IAT_total

    def setFwdIATTotal(self, value):
        self.fwd_IAT_total = int(round(value))

    def getFwdIATMean(self):
        return self.fwd_IAT_mean

    def setFwdIATMean(self, value):
        self.fwd_IAT_mean = float(value)

    def getFwdIATStd(self):
        return self.fwd_IAT_std

    def setFwdIATStd(self, value):
        self.fwd_IAT_std= float(value)

    def getFwdIATMax(self):
        return self.fwd_IAT_max

    def setFwdIATMax(self, value):
        self.fwd_IAT_max = int(round(value))

    def getFwdIATMin(self):
        return self.fwd_IAT_min

    def setFwdIATMin(self, value):
        self.fwd_IAT_min = int(round(value))

    def getBwdIATTotal(self):
        return self.bwd_IAT_total

    def setBwdIATTotal(self, value):
        self.bwd_IAT_total = int(round(value))

    def getBwdIATMean(self):
        return self.bwd_IAT_mean

    def setBwdIATMean(self, value):
        self.bwd_IAT_mean = float(value)

    def getBwdIATStd(self):
        return self.bwd_IAT_std

    def setBwdIATStd(self, value):
        self.bwd_IAT_std= float(value)

    def getBwdIATMax(self):
        return self.bwd_IAT_max

    def setBwdIATMax(self, value):
        self.bwd_IAT_max = int(round(value))

    def getBwdIATMin(self):
        return self.bwd_IAT_min

    def setBwdIATMin(self, value):
        self.bwd_IAT_min = int(round(value))

    def getFwdPSHFlags(self):
        return self.fwd_PSH_flags

    def setFwdPSHFlags(self, value):
        self.fwd_PSH_flags = value

    def getBwdPSHFlags(self):
        return self.bwd_PSH_flags

    def setBwdPSHFlags(self, value):
        self.bwd_PSH_flags = value

    def getFwdURGFlags(self):
        return self.fwd_URG_flags

    def setFwdURGFlags(self, value):
        self.fwd_URG_flags = value

    def getBwdURGFlags(self):
        return self.bwd_URG_flags

    def setBwdURGFlags(self, value):
        self.bwd_URG_flags = value

    def getFwdHeaderLength(self):
        return self.fwd_header_length

    def setFwdHeaderLength(self, value):
        self.fwd_header_length = value

    def getBwdHeaderLength(self):
        return self.bwd_header_length

    def setBwdHeaderLength(self, value):
        self.bwd_header_length = value

    def getDownUpRatio(self):
        return self.down_up_ratio

    def setDownUpRatio(self, value):
        self.down_up_ratio = int(round(value))

    def getMinPacketLen(self):
        return self.min_pack_length

    def setMinPacketLen(self, value):
        self.min_pack_length = value 

    def getMaxPacketLen(self):
        return self.max_pack_length

    def setMaxPacketLen(self, value):
        self.max_pack_length = value    

    def getPacketLenMean(self):
        return self.pack_len_mean

    def setPacketLenMean(self, value):
        self.pack_len_mean = float(value)

    def getPacketLenStd(self):
        return self.pack_len_std

    def setPacketLenStd(self, value):
        self.pack_len_std = float(value)

    def getPacketLenVar(self):
        return self.pack_len_var

    def setPacketLenVar(self, value):
        self.pack_len_var = float(value)

    def getFINFlagCount(self):
        return self.FIN_flag_count

    def setFINFlagCount(self, value):
        self.FIN_flag_count = value

    def getPSHFlagCount(self):
        return self.PSH_flag_count

    def setPSHFlagCount(self, value):
        self.PSH_flag_count = value

    def getSYNFlagCount(self):
        return self.SYN_flag_count

    def setSYNFlagCount(self, value):
        self.SYN_flag_count = value

    def getRSTFlagCount(self):
        return self.RST_flag_count

    def setRSTFlagCount(self, value):
        self.RST_flag_count = value

    def getACKFlagCount(self):
        return self.ACK_flag_count

    def setACKFlagCount(self, value):
        self.ACK_flag_count = value

    def getURGFlagCount(self):
        return self.URG_flag_count

    def setURGFlagCount(self, value):
        self.URG_flag_count = value

    def getCWEFlagCount(self):
        return self.CWE_flag_count

    def setCWEFlagCount(self, value):
        self.CWE_flag_count = value
    
    def getECEFlagCount(self):
        return self.ECE_flag_count

    def setECEFlagCount(self, value):
        self.ECE_flag_count = value

    def getAvgPacketSize(self):
        return self.avg_pack_size

    def setAvgPacketSize(self, value):
        self.avg_pack_size = float(value)

    def getAvgFwdSegmentSize(self):
        return self.avg_fwd_seg_size

    def setAvgFwdSegmentSize(self, value):
        self.avg_fwd_seg_size = float(value)

    def getFwdAvgBytes_Bulk(self):
        return self.fwd_avg_bytes_bulk

    def setFwdAvgBytes_Bulk(self, value):
        self.fwd_avg_bytes_bulk = int(round(value))

    def getFwdAvgPackets_Bulk(self):
        return self.fwd_avg_packets_bulk

    def setFwdAvgPackets_Bulk(self, value):
        self.fwd_avg_packets_bulk = int(round(value))

    def getFwdAvgBulkRate(self):
        return self.fwd_avg_bulk_rate

    def setFwdAvgBulkRate(self, value):
        self.fwd_avg_bulk_rate = int(round(value))

    def getBwdAvgBytes_Bulk(self):
        return self.bwd_avg_bytes_bulk

    def setBwdAvgBytes_Bulk(self, value):
        self.bwd_avg_bytes_bulk = int(round(value))

    def getBwdAvgPackets_Bulk(self):
        return self.bwd_avg_packets_bulk

    def setBwdAvgPackets_Bulk(self, value):
        self.bwd_avg_packets_bulk = int(round(value))

    def getBwdAvgBulkRate(self):
        return self.bwd_avg_bulk_rate

    def setBwdAvgBulkRate(self, value):
        self.bwd_avg_bulk_rate = int(round(value))

    def getAvgBwdSegmentSize(self):
        return self.avg_bwd_seg_size

    def setAvgBwdSegmentSize(self, value):
        self.avg_bwd_seg_size = float(value)

    def getInitWinBytesFwd(self):
        return self.init_win_bytes_fwd

    def setInitWinBytesFwd(self, value):
        self.init_win_bytes_fwd = value

    def getInitWinBytesBwd(self):
        return self.init_win_bytes_bwd

    def setInitWinBytesBwd(self, value):
        self.init_win_bytes_bwd = value

    def getActDataPktFwd(self):
        return self.act_data_pkt_fwd

    def setActDataPktFwd(self, value):
        self.act_data_pkt_fwd = value

    def getMinSegSizeFwd(self):
        return self.min_seg_size_fwd

    def setMinSegSizeFwd(self, value):
        self.min_seg_size_fwd = value

    def getActiveMean(self):
        return self.active_mean

    def setActiveMean(self, value):
        self.active_mean = float(value)

    def getActiveStd(self):
        return self.active_std

    def setActiveStd(self, value):
        self.active_std = float(value)

    def getActiveMax(self):
        return self.active_max

    def setActiveMax(self, value):
        self.active_max = value


    def getActiveMin(self):
        return self.active_min

    def setActiveMin(self, value):
        self.active_min = value

    def getIdleMean(self):
        return self.idle_mean

    def setIdleMean(self, value):
        self.idle_mean = float(value)

    def getIdleStd(self):
        return self.idle_std

    def setIdleStd(self, value):
        self.idle_std = float(value)

    def getIdleMax(self):
        return self.idle_max

    def setIdleMax(self, value):
        self.idle_max = value

    def getIdleMin(self):
        return self.idle_min

    def setIdleMin(self, value):
        self.idle_min = value

    def getSrcIP(self):
        return self.idle_min

    def setIdleMin(self, value):
        self.idle_min = value

    def getSrc(self):
        return self.src

    def getDest(self):
        return self.dest

    def getSrcPort(self):
        return self.src_port

    def getProtocol(self):
        return self.protocol


    def setSrc(self, value):
        self.src = value

    def setDest(self, value):
        self.dest = value

    def setSrcPort(self, value):
        self.src_port = value

    def setProtocol(self, value):
        self.protocol = value

    def setPID(self, value):
        self.pid = value

    def setPName(self, value):
        self.p_name = value

    def getPID(self):
        return self.pid

    def getPName(self):
        return self.p_name        

# packet = packetDetails()
# flow = features()
# # Set the PName attribute (just as an example)
# flow.setPName("Example Name")

# # Get and print the PName attribute
# print(flow.getPName())





        

        

























































