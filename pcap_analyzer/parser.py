import pyshark
from models import File , Packet

def get_interface_name(packet):
    try:
        return packet.frame_info.interface_name
    except:
        return ''

def get_payload(protocol):
    try:
        return parse_hexdata(protocol.payload)
    except:
        return ''

def parse_hexdata(data : str):
    pure_data =  list( filter( lambda x: int(x , 16) >= 32 , data.split(":") ) )
    return "".join([ chr( int(i , 16) )  for i in pure_data ])



def read_pcap( filename ):
    response = []
    with pyshark.FileCapture(filename) as packets:
        for packet in packets:
            if packet.highest_layer == "TCP":
                response.append(
                    Packet.create( 
                        src_ip = packet.ip.src,
                        dst_ip = packet.ip.dst,
                        src_port = int(packet.tcp.srcport),
                        dst_port = int(packet.tcp.dstport),
                        length = int(packet.tcp.len),
                        stream_id = int(packet.tcp.stream),
                        timestamp = float( packet.sniff_timestamp ),
                        time_delta = float( packet.tcp.time_delta ),
                        interface_name = get_interface_name(packet),
                        payload = get_payload(packet.tcp),
                        protocol = "TCP",
                        file_path = filename
                    )
                )
            elif packet.highest_layer == "UDP":
                response.append(
                    Packet.create( 
                        src_ip = packet.ip.src,
                        dst_ip = packet.ip.dst,
                        src_port = int(packet.udp.srcport),
                        dst_port = int(packet.udp.dstport),
                        length = int(packet.udp.length),
                        stream_id = int(packet.udp.stream),
                        timestamp = float( packet.sniff_timestamp ),
                        time_delta = float( packet.udp.time_delta ),
                        interface_name = get_interface_name(packet),
                        payload = get_payload(packet.udp),
                        protocol = "UDP",
                        file_path = filename
                    )
                )
            elif packet.highest_layer == "DNS":
                response.append(
                    Packet.create( 
                        src_ip = packet.ip.src,
                        dst_ip = packet.ip.dst,
                        src_port = int(packet.udp.srcport),
                        dst_port = int(packet.udp.dstport),
                        length = int(packet.udp.length),
                        stream_id = int(packet.udp.stream),
                        timestamp = float( packet.sniff_timestamp ),
                        time_delta = float( packet.udp.time_delta ),
                        interface_name = get_interface_name(packet),
                        payload = get_payload(packet.udp),
                        query_name = packet.dns.qry_name,
                        protocol = "DNS",
                        file_path = filename
                    )
                )
            elif packet.highest_layer == "HTTP":
                http_data = extract_http_information(packet)
                response.append(
                    Packet.create( 
                        src_ip = http_data["source_address"],
                        dst_ip = http_data["destination_address"],
                        src_port = int(packet.tcp.srcport),
                        dst_port = int(packet.tcp.dstport),
                        length = int(packet.tcp.len),
                        stream_id = int(packet.tcp.stream),
                        timestamp = float( packet.sniff_timestamp ),
                        time_delta = float( packet.tcp.time_delta ),
                        interface_name = get_interface_name(packet),
                        payload = get_payload(packet.tcp),
                        http_method = http_data["http_method"],
                        user_agent = http_data["user_agent"],
                        protocol = "HTTP",
                        file_path = filename
                    )
                )
            elif packet.highest_layer == "SMB":
                response.append(
                    Packet.create( 
                        src_ip = packet.ip.src,
                        dst_ip = packet.ip.dst,
                        src_port = int(packet.tcp.srcport),
                        dst_port = int(packet.tcp.dstport),
                        length = int(packet.tcp.len),
                        stream_id = int(packet.tcp.stream),
                        timestamp = float( packet.sniff_timestamp ),
                        time_delta = float( packet.tcp.time_delta ),
                        interface_name = get_interface_name(packet),
                        payload = get_payload(packet.tcp),
                        protocol = "SMB",
                        file_path = filename
                    )
                )
    return response
    
def main():
    Packet.insert_many(read_pcap("test.pcapng")).execute()

if __name__ == "__main__":
    main()