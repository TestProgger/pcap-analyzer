from pprint import pprint

from utils.TypeClasses.ICMP import ICMP

def http_ddos_check( http_data_list : list ):
    cloned_data = http_data_list[:]

    temporary_dict = {}

    while len(cloned_data) > 0:
        item = cloned_data[0]
        src = item["source_address"]
        filtered_data = filter( lambda x : x["source_address"] == src , cloned_data )

        for i in filtered_data:
            if src not in  temporary_dict:
                temporary_dict[src] = {}
            else:
                if i["destination_address"] not in temporary_dict[src]:
                    temporary_dict[src][i["destination_address"]] = 0
                else:
                    temporary_dict[src][i["destination_address"]] += 1
            cloned_data.remove(i)
    if len(temporary_dict.keys()) != 0:
        for src in temporary_dict.keys():
            if len(temporary_dict[src].keys()) == 0:
                continue
            # [ dst for dst in temporary_dict[src].keys()]


    return response


def ddos_analyzer( predefinded_data : list ):
    pass
