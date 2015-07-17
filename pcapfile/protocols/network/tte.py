import ctypes
import struct
import binascii
from pcapfile.protocols.linklayer import ethernet


class TTE(ctypes.Structure):
    """
    Represents an TTE packet.
    """
    _fields_ = [('dst', ctypes.c_char_p),
                ('src', ctypes.c_char_p),
                ('type', ctypes.c_ushort),
                ('integration_cycle', ctypes.c_ulong),
                ('membership_cycle', ctypes.c_ulong),
                ('sync_priority', ctypes.c_ubyte),
                ('sync_domain', ctypes.c_ubyte),
                ('message_type', ctypes.c_char_p),
                ('transparent_clock', ctypes.c_ulonglong),
                ]
    
    def __init__(self, p=None, layers=0):
        
        self.timestamp_ms = p.timestamp_ms
        self.timestamp    = p.timestamp
        if not hasattr(p, 'type'):
            e = ethernet.Ethernet(p.raw())
        else:
            e = p    
        payload = binascii.unhexlify(e.payload)
        assert (e.type == 0x891d) or (len(payload) == 46), 'not a TTE packet.'
        
        self.dst  = e.dst
        self.src  = e.src
        self.type = e.type
        
        fields = struct.unpack('!LL4sBBB5sQ18s', payload[:46])
        #print(fields)
        self.integration_cycle = fields[0]
        self.membership_cycle  = fields[1]
        self.reserved0         = fields[2]
        self.sync_priority     = fields[3]
        self.sync_domain       = fields[4]
        if   0x2 == fields[5]:
            self.message_type = b"integration frame"
        elif 0x4 == fields[5]:
            self.message_type = b"coldstart frame"
        elif 0x8 == fields[5]:
            self.message_type = b"coldstart ack frame"
        else:
            self.message_type = b"unknown"
            print(fields)
            exit()
        
        self.reserved1         = fields[6]
        self.transparent_clock = fields[7]
        self.reserved2         = fields[8]
        
#         if layers:
#             self.load_network(layers)
    
    def __str__(self):
        return 'TTE, IC 0x{:08x}, TC 0x{:016x}, {}'.format(
            self.integration_cycle, 
            self.transparent_clock,
            self.message_type.decode('utf-8'), 
            )
