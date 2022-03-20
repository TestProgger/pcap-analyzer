import re
from modules.Types.Scanner.HTTP_SCAN_RESPONSE import HTTP_SCAN_RESPONSE
from modules.Types.Scanner.TCP_SCAN_RESPONSE import TCP_SCAN_RESPONSE
from utils.TypeClasses.DNS import DNS
from utils.TypeClasses.TCP import TCP
from utils.TypeClasses.UDP import UDP
from typing import Any, Dict , Union

from pprint import pprint

SPECIAL_PORTS = [ 21 , 22 , 23 , 25 ,  33 , 3389 , 3306 , 5432 , 5800 , 5900  ]
SCANNER_HEADERS = [
                    r".*nikto.*" , r".*nmap.*" , r".*goldeneye.*" , 
                    r".*nessus.*" , r".*dirb.*" , r".*dirbuster.*" , 
                    r".*requests.*" , r".*xss.*" , r".*openvas.*" , 
                    r".*greenbone.*" , r".*open vas.*" , r".*open-vas.*"
                ]

def tcp_port_scan_check( tcp_data_list : list[TCP] ) -> list[TCP_SCAN_RESPONSE]:
    pure_data = tcp_data_list[:]
    ip_map = dict()
    while len( pure_data ) > 0:
        item = pure_data[0]
        filtered_data = filter( lambda x : x.ip.src == item.ip.src , pure_data )
        for fd in filtered_data:
            if fd.dst_port not in SPECIAL_PORTS:
                continue
            if fd.ip.src in ip_map :
                if fd.ip.dst in ip_map[fd.ip.src]:    
                    ip_map[fd.ip.src][fd.ip.dst].append(fd.dst_port)
                else:
                    ip_map[fd.ip.src][fd.ip.dst] = []
            else:
                ip_map[fd.ip.src] = {}
            pure_data.remove(fd)
    response = []
    for src in ip_map.keys():
        for dst in ip_map[src]:
            response.append(TCP_SCAN_RESPONSE(src , dst , ip_map[src][dst] ))
    return response

def http_scan_check(http_data_list)-> list[HTTP_SCAN_RESPONSE]:   
    response = []
    for hdt in http_data_list:
        for header in SCANNER_HEADERS:
            if re.match( header , hdt["user_agent"] , re.I | re.M ):
                response.append( HTTP_SCAN_RESPONSE( hdt["source_address"] , hdt["destination_address"] , header ) )
    return response


def scanner_analyzer( data : Dict[str , Any] ) -> tuple[list[TCP_SCAN_RESPONSE] , list[HTTP_SCAN_RESPONSE]]:
    tcp_scan_response = tcp_port_scan_check(data["TCP"])
    http_scan_response = http_scan_check(data["HTTP"])

    return tcp_scan_response ,  http_scan_response
    
    
        


