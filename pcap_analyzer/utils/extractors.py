def extract_http_information(packet):
    response = {}
    try:
        field_names = packet.http._all_fields
        response["http_method"] = {val for key, val in field_names.items() if key == 'http.request.method'}
        response["user_agent"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                           if key == 'http.user_agent'})

        if 'IPv4' in str(packet.layers[0]) and 'HTTP' in str(packet.layers):
            response["source_address"] = packet.ip.src
            response["destination_address"] = packet.ip.dst

        elif 'IPV6' in str(packet.layers) and 'HTTP' in str(packet.layers):
            response["source_address"] = packet.ipv6.src
            response["destination_address"] = packet.ipv6.dst

        return response

    except AttributeError as e:
        pass