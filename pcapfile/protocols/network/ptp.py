import ctypes
import struct
import binascii
from pcapfile.protocols.linklayer import ethernet


class PTP(ctypes.Structure):
    """
    Represents an PTP packet.
    """

    _fields_ = [
                ('v_ptp', ctypes.c_ushort), # ptp version
                ('ptp_version', ctypes.c_ushort),
                ('messageId', ctypes.c_ushort),
                ('message_length', ctypes.c_ushort),
                ('subdomain', ctypes.c_ulong), 
                ('messageType', ctypes.c_ubyte), 
                ('sourceCommunicationTechnology', ctypes.c_ubyte), 
                ('sourceUuid', ctypes.c_ulong), 
                ('sourcePortId', ctypes.c_ubyte), 
                ('sequenceId', ctypes.c_ubyte), 
                ('control', ctypes.c_ubyte), 
                ('flags', ctypes.c_ushort), 
                ('originTimestamp_s', ctypes.c_uint), 
                ('originTimestamp_ns', ctypes.c_uint), 
                ('payload', ctypes.c_char_p),
               ]

    def __init__(self, packet, p=None, layers=0):
        
        if not p == None:
            self.pcap_timestamp_s = p.timestamp
            self.pcap_timestamp_ms = p.timestamp_ms
#             self.pcap_num = pcap_num
#             self.src = i.src
#             self.dst = i.dst

        # parse the required header first, deal with options later
        magic = struct.unpack('!H',packet[2:4])[0]
        assert magic == 319 or magic == 320 , 'not an PTP packet.'

        offset = 8
        fields = struct.unpack('!HHQQBBHHHHHBH', packet[offset:offset+35])
        self.v_ptp = fields[0]
        self.ptp_version = fields[0] & 0xf
        self.messageId = (fields[0] >> 8) & 0xf
        self.message_length = fields[1]
        self.subdomain = fields[3] << 32 | fields[2]
        self.messageType = fields[4]
        self.sourceCommunicationTechnology = fields[5]
        self.sourceUuid = (fields[8] << 16) | (fields[7] << 8) | fields[6]
        self.sourcePortId = fields[9]
        self.sequenceId = fields[10]
        self.control = fields[11]
        self.flags = fields[12]
        
        fields = (0, 0)
        if   self.messageId == 0x0:
            self.message_type = 'Sync'
            if 2 == self.ptp_version:
                fields = struct.unpack('!II', packet[offset+36:offset+44])
            else:
                fields = struct.unpack('!II', packet[offset+40:offset+48])
        elif self.messageId == 0x1:
            self.message_type = 'Delay_Req'
            self.ClockIdentity = struct.unpack('!Q', packet[offset+20:offset+28])[0]
            if 2 == self.ptp_version:
                fields = struct.unpack('!II', packet[offset+36:offset+44])
            else:
                fields = struct.unpack('!II', packet[offset+44:offset+52])
        elif self.messageId == 0x8:
            self.message_type = 'Follow Up'
            if 2 == self.ptp_version:
                fields = struct.unpack('!II', packet[offset+36:offset+44])
            else:
                fields = struct.unpack('!II', packet[offset+44:offset+52])
        elif self.messageId == 0x9:
            self.message_type = 'Delay_Resp'
            self.ClockIdentity = struct.unpack('!Q', packet[offset+20:offset+28])[0]
            self.requestingSourcePortIdentity = struct.unpack('!Q', packet[offset+44:offset+52])[0]
            self.requestingSourcePortId = struct.unpack('!H', packet[offset+52:offset+56])[0]
            if 2 == self.ptp_version:
                fields = struct.unpack('!II', packet[offset+36:offset+44])
            else:
                fields = struct.unpack('!II', packet[offset+44:offset+52])
        elif self.messageId == 0xb:
            self.message_type = 'Announce'
            if 2 == self.ptp_version:
                fields = struct.unpack('!II', packet[offset+36:offset+44])
            else:
                fields = struct.unpack('!II', packet[offset+44:offset+52])
        elif self.messageId == 0xd:
            self.message_type = 'Management Message'
            if 2 == self.ptp_version:
                fields = struct.unpack('!II', packet[offset+36:offset+44])
            else:
                fields = struct.unpack('!II', packet[offset+44:offset+52])
        else:
            print("Unknown messageId 0x{0:x}".format(self.messageId))
            raise Exception
                   
        self.originTimestamp_s = fields[0]
        self.originTimestamp_ns = fields[1]
        
        #self.pcap_timestamp  = self.pcap_timestamp_s  + self.pcap_timestamp_ms/1000000.0
        self.originTimestamp = self.originTimestamp_s + self.originTimestamp_ns/1000000000.0


    def __str__(self):
        packet = 'PTP {0} packet @ {1}.{2}'.format(self.message_type,self.originTimestamp_s,self.originTimestamp_ns)
        return packet
