from pyshark.packet.packet import Packet

from utils.decoders import parse_hexdata

from .Ethernet import Ethernet
from .IP import IP

class DNS:
    def __init__(self , dns_packet : Packet ) -> None:
        self.query_name = dns_packet.dns.qry_name
        self.ip = IP(dns_packet.ip)
        self.eth = Ethernet(dns_packet.eth)

        if int(dns_packet.udp.length) > 2:
            self.payload = parse_hexdata( dns_packet.udp.payload)
        else:
            self.payload = ''