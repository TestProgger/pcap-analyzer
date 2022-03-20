from pyshark.packet.packet import Packet
class IP:
    def __init__(self , ip_packet) -> None:
        self.dst : str = ip_packet.dst
        self.src : str = ip_packet.src
        self.version : int = int(ip_packet.version)
        self.ttl : int = int(ip_packet.ttl)