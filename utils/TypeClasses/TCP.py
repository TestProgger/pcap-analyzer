from .IP import IP
from pyshark.packet.packet import Packet

from utils.TypeClasses.Ethernet import Ethernet
from utils.decoders import parse_hexdata
class TCP:
    def __init__(self , tcp_packet : Packet) -> None:
        self.src_port : int = int(tcp_packet.tcp.srcport)
        self.dst_port : int = int(tcp_packet.tcp.dstport)
        self.length : int = int(tcp_packet.tcp.len)
        if int(tcp_packet.tcp.len) > 2:
            self.payload : str = parse_hexdata( tcp_packet.tcp.payload )
        else:
            self.payload : str = ''
        self.ip = IP(tcp_packet.ip)
        self.eth = Ethernet(tcp_packet.eth)