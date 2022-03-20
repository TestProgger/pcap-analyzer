from utils.TypeClasses.Ethernet import Ethernet
from utils.TypeClasses.Frame import Frame
from utils.TypeClasses.IP import IP
from utils.decoders import parse_hexdata

class UDP:
    def __init__(self, udp_packet) -> None:
        self.length = int(udp_packet.udp.length)
        self.timestamp :float =  float( udp_packet.sniff_timestamp )
        self.time_delta = udp_packet.udp.time_delta
        self.stream = udp_packet.udp.stream
        if int(udp_packet.udp.length) > 2:
            self.payload : str  = parse_hexdata(udp_packet.udp.payload)
        else:
            self.payload : str = ''

        self.ip = IP(udp_packet.ip)
        self.eth = Ethernet(udp_packet.eth)
        self.frame = Frame(udp_packet.frame_info)