from utils.TypeClasses.DNS import DNS
from utils.TypeClasses.TCP import TCP
from utils.TypeClasses.UDP import UDP
from typing import Dict , Union

SPECIAL_PORTS = [ 21 , 22 , 23 , 25 ,  33 , 80 , 443 , 3389 , 3306 , 5432 , 5800 , 5900  ]


def tcp_port_scan_check( tcp_data_list : list[TCP] ):
    pure_data = tcp_data_list[:]

    while len( pure_data ) > 0:
        item = pure_data[0]
        filtered_data = filter( lambda x : x.ip.src == item.ip.src , pure_data )
        print(filtered_data)
        ip_map = dict()
        for fd in filtered_data:
            if(  fd.ip.src in ip_map ):
                ip_map[fd.ip.dst].append( fd.dest_port )
            else:
                ip_map[fd.ip.dst] = []
            pure_data.remove(fd)
    print(ip_map)



def dns_bruteforce_check(dns_data_list : list[DNS]):
    a = 2

def scanner_analyzer( data : Dict[str , Union[UDP , DNS , TCP ]] ):    
    tcp_data_list : list = data["TCP"]

    tcp_port_scan_check(tcp_data_list)
    
    
        


