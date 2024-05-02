import statistics

from AIDS.features import features
# from features import features

from datetime import datetime
threshold = 5

class Flow:
    def __init__(self, packet):
        self.packetInfos = [packet]
        self.fwdPacketInfos = [packet]
        self.bwdPacketInfos = []                                                                                                                    

        self.flowFeatures = features()
        self.flowFeatures.setDestPort(packet.getDestPort())

        self.flowFeatures.setPID(packet.getPID())
        self.flowFeatures.setPName(packet.getPName())

        self.flowFeatures.setFwdPSHFlags(0 if not packet.getPSHFlag() else 1)
        self.flowFeatures.setBwdPSHFlags(0 if not packet.getPSHFlag() else 1)

        self.flowFeatures.setFwdURGFlags(0 if not packet.getURGFlag() else 1)
        self.flowFeatures.setBwdURGFlags(0 if not packet.getURGFlag() else 1)

        self.flowFeatures.setFwdHeaderLength(packet.getHeaderBytes())

        self.flowFeatures.setMaxPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setMinPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setPacketLenMean(packet.getPayloadBytes())
        self.flowFeatures.setMinSegSizeFwd(packet.getHeaderBytes())
        self.flowFeatures.setFINFlagCount(1 if packet.getFINFlag() else 0)
        self.flowFeatures.setSYNFlagCount(1 if packet.getSYNFlag() else 0)
        self.flowFeatures.setRSTFlagCount(1 if packet.getRSTFlag() else 0)
        self.flowFeatures.setPSHFlagCount(1 if packet.getPSHFlag() else 0)
        self.flowFeatures.setACKFlagCount(1 if packet.getACKFlag() else 0)
        self.flowFeatures.setURGFlagCount(1 if packet.getURGFlag() else 0)
        self.flowFeatures.setCWEFlagCount(1 if packet.getCWEFlag() else 0)
        self.flowFeatures.setECEFlagCount(1 if packet.getECEFlag() else 0)

        self.flowFeatures.setAvgPacketSize(packet.getPacketSize())
        self.flowFeatures.setInitWinBytesFwd(packet.getWinBytes())
        
        self.flowFeatures.setFwdPacketLenMax(packet.getPayloadBytes())
        self.flowFeatures.setFwdPacketLenMin(packet.getPayloadBytes())
        self.flowFeatures.setTotalLengthofFwdPacket(packet.getPayloadBytes())
        self.flowFeatures.setTotalLengthofBwdPacket(packet.getPayloadBytes())

        self.flowFeatures.setSrc(packet.getSrc())
        self.flowFeatures.setDest(packet.getDest())
        self.flowFeatures.setSrcPort(packet.getSrcPort())
        self.flowFeatures.setProtocol(packet.getProtocol())


        self.flowLastSeen = packet.getTimestamp()
        self.fwdLastSeen = packet.getTimestamp()
        self.bwdLastSeen = 0
        self.flowStartTime = packet.getTimestamp()
        self.startActiveTime = packet.getTimestamp()
        self.endActiveTime = packet.getTimestamp()

        self.flowIAT = []
        self.fwdIAT = []
        self.bwdIAT = []
        self.flowActive = []
        self.flowIdle = []

        self.packet_count = 1
        self.fwd_packet_count = 1
        self.act_fwd_pkt_count = 1
        self.bwd_packet_count = 0
        

    def getFlowLastSeen(self):
        return self.flowLastSeen

    def getFlowStartTime(self):
        return self.flowStartTime

    def new(self, packetInfo, direction):

        if direction == 'bwd':
            self.bwdPacketInfos.append(packetInfo)

            if self.bwd_packet_count == 0:
                # first backward packet, do some initalising
                self.flowFeatures.setBwdPacketLenMax(packetInfo.getPayloadBytes())
                self.flowFeatures.setBwdPacketLenMin(packetInfo.getPayloadBytes())
                self.flowFeatures.setInitWinBytesBwd(packetInfo.getWinBytes())
                self.flowFeatures.setBwdHeaderLength(packetInfo.getHeaderBytes())
            else:
                self.flowFeatures.setBwdPacketLenMax(
                    max(self.flowFeatures.bwd_packet_len_max, packetInfo.getPayloadBytes()))
                self.flowFeatures.setBwdPacketLenMin(
                    min(self.flowFeatures.bwd_packet_len_min, packetInfo.getPayloadBytes()))
                
                self.bwdIAT.append((packetInfo.getTimestamp() - self.bwdLastSeen) * 1000 * 1000)
                self.flowFeatures.setBwdPSHFlags(max(1 if packetInfo.getPSHFlag() else 0,
                                                 self.flowFeatures.getBwdPSHFlags()))
                self.flowFeatures.setBwdURGFlags(max(1 if packetInfo.getURGFlag() else 0,
                                                 self.flowFeatures.getBwdPSHFlags()))

            self.bwd_packet_count = self.bwd_packet_count + 1
            self.flowFeatures.setTotalBwdPacket(self.bwd_packet_count)
            self.bwdLastSeen = packetInfo.getTimestamp()

        else:
            self.fwdPacketInfos.append(packetInfo)
            self.flowFeatures.setFwdPacketLenMax(
                max(self.flowFeatures.fwd_packet_len_max, packetInfo.getPayloadBytes()))
            self.flowFeatures.setBwdPacketLenMin(
                min(self.flowFeatures.fwd_packet_len_min, packetInfo.getPayloadBytes()))
            self.flowFeatures.setMinSegSizeFwd(
                    min(self.flowFeatures.min_seg_size_fwd, packetInfo.getHeaderBytes()))
            self.fwdIAT.append((packetInfo.getTimestamp() - self.fwdLastSeen) * 1000 * 1000)

            self.flowFeatures.setFwdPSHFlags(max(1 if packetInfo.getPSHFlag() else 0,
                                                 self.flowFeatures.getFwdPSHFlags()))
            self.flowFeatures.setFwdURGFlags(max(1 if packetInfo.getURGFlag() else 0,
                                                 self.flowFeatures.getFwdPSHFlags()))

            self.fwd_packet_count = self.fwd_packet_count + 1
            self.flowFeatures.setTotalFwdPacket(self.fwd_packet_count)
            self.fwdLastSeen = packetInfo.getTimestamp()

        self.flowFeatures.setMaxPacketLen(max(self.flowFeatures.getMaxPacketLen(), packetInfo.getPayloadBytes()))
        self.flowFeatures.setMinPacketLen(min(self.flowFeatures.getMinPacketLen(), packetInfo.getPayloadBytes()))

        if packetInfo.getFINFlag():
            self.flowFeatures.setFINFlagCount(1)
        if packetInfo.getSYNFlag():
            self.flowFeatures.setSYNFlagCount(1)
        if packetInfo.getPSHFlag():
            self.flowFeatures.setPSHFlagCount(1)
        if packetInfo.getACKFlag():
            self.flowFeatures.setACKFlagCount(1)
        if packetInfo.getURGFlag():
            self.flowFeatures.setURGFlagCount(1)

        time = packetInfo.getTimestamp()
        if time - self.endActiveTime > threshold:
            if self.endActiveTime - self.startActiveTime > 0:
                self.flowActive.append(self.endActiveTime - self.startActiveTime)
            self.flowIdle.append(time - self.endActiveTime)
            self.startActiveTime = time
            self.endActiveTime = time
        else:
            self.endActiveTime = time

        self.packet_count = self.packet_count + 1
        self.packetInfos.append(packetInfo)
        self.flowIAT.append((packetInfo.getTimestamp() - self.flowLastSeen) * 1000 * 1000)
        self.flowLastSeen = packetInfo.getTimestamp()
        

    def terminated(self):
        duration = (self.flowLastSeen - self.flowStartTime) * 1000 * 1000
        self.flowFeatures.setFlowDuration(duration)

        bwd_packet_sizes =[x.getPacketSize() for x in self.bwdPacketInfos]

        bwd_packet_lens = [x.getPayloadBytes() for x in self.bwdPacketInfos]
        if len(bwd_packet_lens) > 0:
            self.flowFeatures.setTotalLengthofBwdPacket(sum(bwd_packet_lens))
            self.flowFeatures.setBwdPacketLenMean(statistics.mean(bwd_packet_lens))
            if len(bwd_packet_lens) > 1:
                self.flowFeatures.setBwdPacketLenStd(statistics.stdev(bwd_packet_lens))
        
        bwd_header_lens = [x.getHeaderBytes() for x in self.bwdPacketInfos]
        if len(bwd_header_lens) > 0:
            self.flowFeatures.setBwdHeaderLength(sum(bwd_header_lens))

        fwd_packet_sizes =[x.getPacketSize() for x in self.fwdPacketInfos]

        fwd_packet_lens = [x.getPayloadBytes() for x in self.fwdPacketInfos]
        if len(fwd_packet_lens) > 0:
            self.flowFeatures.setTotalLengthofFwdPacket(sum(fwd_packet_lens))
            self.flowFeatures.setFwdPacketLenMean(statistics.mean(fwd_packet_lens))
            if len(fwd_packet_lens) > 1:
                self.flowFeatures.setFwdPacketLenStd(statistics.stdev(fwd_packet_lens))
            for data in fwd_packet_lens:
                if data > 0:
                    self.act_fwd_pkt_count += 1
        
        self.flowFeatures.setActDataPktFwd(self.act_fwd_pkt_count)
        
        fwd_header_lens = [x.getHeaderBytes() for x in self.fwdPacketInfos]
        if len(fwd_header_lens) > 0:
            self.flowFeatures.setFwdHeaderLength(sum(fwd_header_lens))

        if len(self.flowIAT) > 0:
            self.flowFeatures.setFlowIATMean(statistics.mean(self.flowIAT))
            self.flowFeatures.setFlowIATMax(max(self.flowIAT))
            self.flowFeatures.setFlowIATMin(min(self.flowIAT))
            if len(self.flowIAT) > 1:
                self.flowFeatures.setFlowIATStd(statistics.stdev(self.flowIAT))

        if len(self.fwdIAT) > 0:
            self.flowFeatures.setFwdIATTotal(sum(self.fwdIAT))
            self.flowFeatures.setFwdIATMean(statistics.mean(self.fwdIAT))
            self.flowFeatures.setFwdIATMax(max(self.fwdIAT))
            self.flowFeatures.setFwdIATMin(min(self.fwdIAT))
            if len(self.fwdIAT) > 1:
                self.flowFeatures.setFwdIATStd(statistics.stdev(self.fwdIAT))

        if len(self.bwdIAT) > 0:
            self.flowFeatures.setBwdIATTotal(sum(self.bwdIAT))
            self.flowFeatures.setBwdIATMean(statistics.mean(self.bwdIAT))
            self.flowFeatures.setBwdIATMax(max(self.bwdIAT))
            self.flowFeatures.setBwdIATMin(min(self.bwdIAT))
            if len(self.bwdIAT) > 1:
                self.flowFeatures.setBwdIATStd(statistics.stdev(self.bwdIAT))

        self.flowFeatures.setFwdPackets_s(0 if duration == 0 else self.fwd_packet_count / (duration / (1000 * 1000)))
        self.flowFeatures.setBwdPackets_s(0 if duration == 0 else self.bwd_packet_count / (duration / (1000 * 1000)))

        self.flowFeatures.setDownUpRatio(0 if sum(bwd_packet_sizes) == 0 else sum(fwd_packet_sizes) / sum(bwd_packet_sizes))

        packet_lens = [x.getPayloadBytes() for x in self.packetInfos]
        if len(packet_lens) > 0:
            self.flowFeatures.setPacketLenMean(statistics.mean(packet_lens))
            if len(packet_lens) > 1:
                self.flowFeatures.setPacketLenStd(statistics.stdev(packet_lens))
                self.flowFeatures.setPacketLenVar(statistics.variance(packet_lens))

        packet_sizes =[x.getPacketSize() for x in self.packetInfos]
        self.flowFeatures.setAvgPacketSize(sum(packet_sizes) / self.packet_count)

        self.flowFeatures.setFlowBytes_s(0 if duration == 0 else sum(packet_lens) / (duration / (1000 * 1000)))
        self.flowFeatures.setFlowPacket_s(0 if duration == 0 else self.packet_count / (duration / (1000 * 1000)))

        if self.fwd_packet_count > 0 and sum(fwd_packet_lens) > 0:
            self.flowFeatures.setAvgFwdSegmentSize(sum(fwd_packet_lens) / self.fwd_packet_count)
            self.flowFeatures.setFwdAvgBytes_Bulk((sum(fwd_packet_lens) / self.fwd_packet_count)/sum(fwd_packet_lens))
            self.flowFeatures.setFwdAvgPackets_Bulk((sum(fwd_packet_lens) / self.fwd_packet_count)/self.fwd_packet_count)
            self.flowFeatures.setFwdAvgBulkRate(0 if duration == 0 else (sum(fwd_packet_lens) / (duration / (1000 * 1000))) / self.fwd_packet_count)

        if self.bwd_packet_count > 0 and sum(bwd_packet_lens) > 0:
            self.flowFeatures.setAvgBwdSegmentSize(sum(bwd_packet_lens) / self.bwd_packet_count)
            self.flowFeatures.setBwdAvgBytes_Bulk((sum(bwd_packet_lens) / self.bwd_packet_count)/sum(bwd_packet_lens))
            self.flowFeatures.setBwdAvgPackets_Bulk((sum(bwd_packet_lens) / self.bwd_packet_count)/self.bwd_packet_count)
            self.flowFeatures.setBwdAvgBulkRate(0 if duration == 0 else (sum(bwd_packet_lens) / (duration / (1000 * 1000))) / self.bwd_packet_count)

        if len(self.flowActive) > 0:
            self.flowFeatures.setActiveMean(statistics.mean(self.flowActive))
            self.flowFeatures.setActiveMax(max(self.flowActive))
            self.flowFeatures.setActiveMin(min(self.flowActive))
            if len(self.flowActive) > 1:
                self.flowFeatures.setIdleStd(statistics.stdev(self.flowActive))

        if len(self.flowIdle) > 0:
            self.flowFeatures.setIdleMean(statistics.mean(self.flowIdle))
            self.flowFeatures.setIdleMax(max(self.flowIdle))
            self.flowFeatures.setIdleMin(min(self.flowIdle))
            if len(self.flowIdle) > 1:
                self.flowFeatures.setIdleStd(statistics.stdev(self.flowIdle))
        # print("Count: ",self.packet_count)
        return [
                # self.flowLastSeen,
                # self.flowStartTime,
                self.flowFeatures.getDestPort(),
                self.flowFeatures.getFlowDuration(),
                self.flowFeatures.getTotalFwdPacket(),
                self.flowFeatures.getTotalBwdPacket(),
                self.flowFeatures.getTotalLengthofFwdPacket(),
                self.flowFeatures.getTotalLengthofBwdPacket(),
                self.flowFeatures.getFwdPacketLenMax(),
                self.flowFeatures.getFwdPacketLenMin(),
                self.flowFeatures.getFwdPacketLenMean(),
                self.flowFeatures.getFwdPacketLenStd(),
                self.flowFeatures.getBwdPacketLenMax(),
                self.flowFeatures.getBwdPacketLenMin(),
                self.flowFeatures.getBwdPacketLenMean(),
                self.flowFeatures.getBwdPacketLenStd(),
                self.flowFeatures.getFlowBytes_s(),
                self.flowFeatures.getFlowPacket_s(),
                self.flowFeatures.getFlowIATMean(),
                self.flowFeatures.getFlowIATStd(),
                self.flowFeatures.getFlowIATMax(),
                self.flowFeatures.getFlowIATMin(),

                self.flowFeatures.getFwdIATTotal(),
                self.flowFeatures.getFwdIATMean(),
                self.flowFeatures.getFwdIATStd(),
                self.flowFeatures.getFwdIATMax(),
                self.flowFeatures.getFwdIATMin(),
                
                self.flowFeatures.getBwdIATTotal(),
                self.flowFeatures.getBwdIATMean(),
                self.flowFeatures.getBwdIATStd(),
                self.flowFeatures.getBwdIATMax(),
                self.flowFeatures.getBwdIATMin(),

                self.flowFeatures.getFwdPSHFlags(),
                self.flowFeatures.getBwdPSHFlags(),
                self.flowFeatures.getFwdURGFlags(),
                self.flowFeatures.getBwdURGFlags(),

                self.flowFeatures.getFwdHeaderLength(),
                self.flowFeatures.getBwdHeaderLength(),

                self.flowFeatures.getFwdPackets_s(),
                self.flowFeatures.getBwdPackets_s(),
                
                self.flowFeatures.getMinPacketLen(),
                self.flowFeatures.getMaxPacketLen(),
                self.flowFeatures.getPacketLenMean(),
                self.flowFeatures.getPacketLenStd(),
                self.flowFeatures.getPacketLenVar(),
                
                self.flowFeatures.getFINFlagCount(),
                self.flowFeatures.getSYNFlagCount(),
                self.flowFeatures.getRSTFlagCount(),
                self.flowFeatures.getPSHFlagCount(),
                self.flowFeatures.getACKFlagCount(),
                self.flowFeatures.getURGFlagCount(),
                self.flowFeatures.getCWEFlagCount(),
                self.flowFeatures.getECEFlagCount(),

                self.flowFeatures.getDownUpRatio(),

                self.flowFeatures.getAvgPacketSize(),
                self.flowFeatures.getAvgFwdSegmentSize(),
                self.flowFeatures.getAvgBwdSegmentSize(),
                self.flowFeatures.getFwdHeaderLength(),

                self.flowFeatures.getFwdAvgBytes_Bulk(),
                self.flowFeatures.getFwdAvgPackets_Bulk(),
                self.flowFeatures.getFwdAvgBulkRate(),

                self.flowFeatures.getBwdAvgBytes_Bulk(),
                self.flowFeatures.getBwdAvgPackets_Bulk(),
                self.flowFeatures.getBwdAvgBulkRate(),

                self.flowFeatures.getTotalFwdPacket(),
                self.flowFeatures.getTotalLengthofFwdPacket(),
                self.flowFeatures.getTotalBwdPacket(),
                self.flowFeatures.getTotalLengthofBwdPacket(),

                self.flowFeatures.getInitWinBytesFwd(),
                self.flowFeatures.getInitWinBytesBwd(),

                self.flowFeatures.getActDataPktFwd(),
                self.flowFeatures.getMinSegSizeFwd(),

                self.flowFeatures.getActiveMean(),
                self.flowFeatures.getActiveStd(),
                self.flowFeatures.getActiveMax(),
                self.flowFeatures.getActiveMin(),

                self.flowFeatures.getIdleMean(),
                self.flowFeatures.getIdleStd(),
                self.flowFeatures.getIdleMax(),
                self.flowFeatures.getIdleMin(),
                
                # self.flowFeatures.getSrc(),
                # self.flowFeatures.getSrcPort(),
                # self.flowFeatures.getDest(),
                # self.flowFeatures.getProtocol(),
                # datetime.fromtimestamp(self.getFlowStartTime()),
                # datetime.fromtimestamp(self.getFlowLastSeen()),
                
                # self.flowFeatures.getPName(),
                # self.flowFeatures.getPID(),
                ]
