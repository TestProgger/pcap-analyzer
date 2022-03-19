

from fileinput import filename
from pprint import pprint
import pyshark
from modules.scanner_analyzer import tcp_port_scan_check
from utils.TypeClasses.DNS import DNS
from utils.TypeClasses.TCP import TCP
from utils.TypeClasses.UDP import UDP
from utils.TypeClasses.ICMP import ICMP
from utils.decoders import parse_hexdata

# DEFINED_LAYERS = ["TCP" , "ARP" , "TLS" , "DATA" , "ICMP" , "DNS"]



def read_pcap( pcap_file : str ):
    DEFINED_LAYERS_DICT = {
        "TCP" : [],
        "UDP" : [],
        "DNS" : [],
        "ICMP" : []
    }
    with pyshark.FileCapture(pcap_file) as packets:
        for packet in packets:
            print(packet.transport_layer)
            if packet.highest_layer == "TCP":
                DEFINED_LAYERS_DICT["TCP"].append( TCP(packet) )
            elif packet.highest_layer == "UDP":
                DEFINED_LAYERS_DICT["UDP"].append(UDP(packet))
            elif packet.highest_layer == "DNS":
                DEFINED_LAYERS_DICT["DNS"].append(DNS(packet))
            elif packet.highest_layer == "ICMP":
                DEFINED_LAYERS_DICT["ICMP"].append( ICMP(packet) )
            elif packet.highest_layer == "HTTP":
                print(packet)

                

if __name__ == "__main__":
   read_pcap("test.pcapng")
    

