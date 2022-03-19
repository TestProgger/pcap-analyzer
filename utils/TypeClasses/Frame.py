class Frame:
    def __init__(self , frame_packet) -> None:
        self.interface_name : str = frame_packet.interface_name