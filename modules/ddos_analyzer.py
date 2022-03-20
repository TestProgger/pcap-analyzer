from pprint import pprint
from urllib import response

from utils.TypeClasses.ICMP import ICMP

def http_ddos_check( http_data_list : list ):
    cloned_data = http_data_list[:]

    response = {}

    while len(cloned_data) > 0:
        item = cloned_data[0]
        src = item["source_address"]
        filtered_data = filter( lambda x : x["source_address"] == src , cloned_data )

        for i in filtered_data:
            if src not in  response:
                response[src] = {}
            else:
                if i["destination_address"] not in response[src]:
                    response[src][i["destination_address"]] = 0
                else:
                    response[src][i["destination_address"]] += 1
            cloned_data.remove(i)
    return response


def ddos_analyzer( predefinded_data : list ):
    pass
