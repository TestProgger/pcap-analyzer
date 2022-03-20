from pyshark.packet.packet import Packet
from utils.TypeClasses.UDP import UDP

from utils.decoders import parse_hexdata

from .Ethernet import Ethernet
from .IP import IP

class DNS:
    def __init__(self , dns_packet : Packet ) -> None:
        self.query_name : str = dns_packet.dns.qry_name
        self.timestamp : float = float( dns_packet.sniff_timestamp )
        self.ip : IP = IP(dns_packet.ip)
        self.eth : Ethernet = Ethernet(dns_packet.eth)
        self.udp: UDP = UDP(dns_packet)