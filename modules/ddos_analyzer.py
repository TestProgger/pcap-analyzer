def ddos_analyzer( predefinded_data : list ):
    if "ip" in predefinded_data:
        if predefinded_data["ip"]["version"] == "4":
            src_ip = predefinded_data["ip"]["src"]
            dst_ip = predefinded_data["ip"]["dst"]
