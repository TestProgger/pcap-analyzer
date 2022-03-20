import pyshark
from modules.ddos_analyzer import http_ddos_check
from modules.malware_analyzer import dns_tunel_check
from utils.TypeClasses.DNS import DNS
from utils.TypeClasses.TCP import TCP
from utils.TypeClasses.UDP import UDP
from utils.TypeClasses.ICMP import ICMP
from utils.TypeClasses.SMB import SMB
from utils.extractors import extract_http_information
from modules.scanner_analyzer import http_scan_check, scanner_analyzer

from pprint import pprint
from utils.decoders import parse_hexdata

def read_pcap( pcap_file : str ):
    DEFINED_LAYERS_DICT = {
        "TCP" : [],
        "UDP" : [],
        "DNS" : [],
        "ICMP" : [],
        "HTTP" : [],
        "SMB" : []
    }
    with pyshark.FileCapture(pcap_file) as packets:
        for packet in packets:

            if packet.highest_layer == "TCP":
                DEFINED_LAYERS_DICT["TCP"].append( TCP(packet) )
            elif packet.highest_layer == "UDP":
                DEFINED_LAYERS_DICT["UDP"].append(UDP(packet))
            elif packet.highest_layer == "DNS":
                DEFINED_LAYERS_DICT["DNS"].append(DNS(packet))
            elif packet.highest_layer == "ICMP":
                DEFINED_LAYERS_DICT["ICMP"].append( ICMP(packet) )
            elif packet.highest_layer == "HTTP":
                DEFINED_LAYERS_DICT["HTTP"].append(extract_http_information(packet))
            elif packet.highest_layer == "SMB":
                DEFINED_LAYERS_DICT["SMB"].append( SMB(packet) )
    return DEFINED_LAYERS_DICT
                

if __name__ == "__main__":

    # print()

    formatted_data = read_pcap("smb_putty_xfer.pcap")
#    scanner_analyzer( formatted_data )
    # http_ddos_check(formatted_data["HTTP"])
    # http_scan_check(formatted_data["HTTP"])
    print(dns_tunel_check(formatted_data["DNS"]))
    

