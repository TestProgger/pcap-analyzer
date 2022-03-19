import pyshark
from utils.TypeClasses.DNS import DNS
from utils.TypeClasses.TCP import TCP
from utils.TypeClasses.UDP import UDP
from utils.TypeClasses.ICMP import ICMP
from utils.extractors import extract_http_information
from modules.scanner_analyzer import scanner_analyzer



def read_pcap( pcap_file : str ):
    DEFINED_LAYERS_DICT = {
        "TCP" : [],
        "UDP" : [],
        "DNS" : [],
        "ICMP" : [],
        "HTTP" : []
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
                DEFINED_LAYERS_DICT["HTTP"] = extract_http_information(packet)

    return DEFINED_LAYERS_DICT
                

if __name__ == "__main__":
   formatted_data = read_pcap("test.pcapng")
   scanner_analyzer( formatted_data )
    

