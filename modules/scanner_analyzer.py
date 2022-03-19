import re
from utils.TypeClasses.DNS import DNS
from utils.TypeClasses.TCP import TCP
from utils.TypeClasses.UDP import UDP
from typing import Dict , Union

LOCAL_IP = ''

def tcp_port_scan_check( tcp_data_list : list[TCP] ):
    pure_data = list( filter( lambda x : x.ip.src != LOCAL_IP , tcp_data_list ) )

    while len(pure_data) > 0:
        item = pure_data[0]
        filtered_data  = filter( lambda x: x.ip.src == item.ip.src )
        grouped_by_src_ip = []
        for fd in filtered_data:
            grouped_by_src_ip.append(fd.dst_port)
            pure_data.remove(fd)
        
        if len( set( grouped_by_src_ip ) ) > 3:
            return True , item.ip.src
    return False , None

def scanner_analyzer( data : Dict[str , Union[UDP , DNS , TCP ]] ):
    global LOCAL_IP
    
    tcp_data_list : list = data["TCP"]
    if len(data["DNS"]):
        LOCAL_IP = data["DNS"][0].ip.src
    
    
        


