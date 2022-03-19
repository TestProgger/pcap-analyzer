

from pprint import pprint
import pyshark
from utils.TypeClasses.DNS import DNS
from utils.TypeClasses.TCP import TCP
from utils.TypeClasses.UDP import UDP

pyshark.packet.packet.Packet

DEFINED_LAYERS = ["TCP" , "ARP" , "TLS" , "UDP" , "ICMP" , "DNS"]
DEFINED_LAYERS_DICT = {
    "TCP" : [],
    "ARP" : [],
    "TLS" : [],
    "UDP" : [],
    "ICMP" : [],
    "DNS" : []
}
if __name__ == "__main__":
    cap  = pyshark.FileCapture('test.pcap')

    for i in cap:
        highest_layer_name = i.highest_layer
        if highest_layer_name == "DNS":
            DEFINED_LAYERS_DICT["DNS"].append( DNS(i) )
        elif highest_layer_name == "TCP":
            DEFINED_LAYERS_DICT["TCP"].append( TCP(i) )
        elif highest_layer_name == "DATA":
            DEFINED_LAYERS_DICT["UDP"].append( UDP(i) )
        # break
    print([ i.payload for i in DEFINED_LAYERS_DICT["UDP"]])
            


