class Frame:
    def __init__(self , frame_packet) -> None:
        if  hasattr( frame_packet , "interface_name"):
            self.interface_name : str = frame_packet.interface_name
        else:
            self.interface_name : str = ''