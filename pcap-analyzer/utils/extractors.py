from urllib import response


def extract_http_information(packet):
    response = {}
    try:
        if 'IPv4' in str(packet.layers[0]) and 'HTTP' in str(packet.layers):
            response["source_address"] = packet.ip.src
            response["destination_address"] = packet.ip.dst
            field_names = packet.http._all_fields
            http_method = {val for key, val in field_names.items() if key == 'http.request.method'}
            response["http_method"] = http_method
            if 'GET' in str(http_method):
                response["user_agent"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                       if key == 'http.user_agent'})

                response["host"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.host'})

                response["http_referer"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                         if key == 'http.referer'})

                response["url_requested"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                          if key == 'http.request.full_uri'})

                response["query_parameter"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                            if key == 'http.request.uri.query'})

                response["cookie"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.cookie'})

                response["cookie_pair"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                        if key == 'http.cookie_pair'})

            elif 'POST' in str(http_method):
                response["user_agent"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                       if key == 'http.user_agent'})

                response["host"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.host'})

                response["http_referer"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                         if key == 'http.referer'})

                response["http_content_type"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                              if key == 'http.request.full_uri'})

                response["query_parameter"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                            if key == 'http.request.uri.query'})

                response["cookie"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.cookie'})

                response["cookie_pair"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                        if key == 'http.cookie_pair'})

                response["http_data"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                      if key == 'http.file_data'})

        elif 'IPV6' in str(packet.layers) and 'HTTP' in str(packet.layers):
            response["source_address"] = packet.ipv6.src
            response["destination_address"] = packet.ipv6.dst
            field_names = packet.http._all_fields
            http_method = {val for key, val in field_names.items() if key == 'http.request.method'}
            response["http_method"] = http_method
            if 'GET' in str(http_method):
                response["user_agent"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                       if key == 'http.user_agent'})

                response["host"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.host'})

                response["http_referer"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                         if key == 'http.referer'})

                response["url_requested"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                          if key == 'http.request.full_uri'})

                response["query_parameter"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                            if key == 'http.request.uri.query'})

                response["cookie"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.cookie'})

                response["cookie_pair"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                        if key == 'http.cookie_pair'})

                response["http_data"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                      if key == 'http.file_data'})

            elif 'POST' in str(http_method):
                response["user_agent"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                       if key == 'http.user_agent'})

                response["host"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.host'})

                response["http_referer"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                         if key == 'http.referer'})

                response["http_content_type"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                              if key == 'http.request.full_uri'})

                response["url_requested"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                            if key == 'http.request.uri.query'})

                response["cookie"] = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'http.cookie'})

                response["cookie_pair"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                        if key == 'http.cookie_pair'})

                response["http_data"] = ' '.join(str(e) for e in {val for key, val in field_names.items()
                                                      if key == 'http.file_data'})
        response["time_delta"] = float(packet.tcp.time_delta)
        response["timestamp"] = float(packet.sniff_timestamp)
        return  response

    except AttributeError as e:
        pass