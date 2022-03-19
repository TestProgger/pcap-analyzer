class Ethernet:
    def __init__(self , eth_packet):
        self.src = eth_packet.src
        self.dst = eth_packet.dst