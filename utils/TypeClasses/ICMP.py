from pyshark.packet.packet import Packet
from utils.decoders import parse_hexdata

from .Ethernet import Ethernet
from .IP import IP
class ICMP:
    def __init__(self , icmp_packet : Packet ) -> None:
        self.resp_time  = float( icmp_packet.icmp.resptime ) 
        self.timestamp   =  float( icmp_packet.sniff_timestamp )
        self.ip= IP(icmp_packet.ip)
        self.eth  = Ethernet(icmp_packet.eth)