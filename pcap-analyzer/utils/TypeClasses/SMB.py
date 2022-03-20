from .TCP import TCP


class SMB:
    def __init__(self , smb_packet) -> None:
        self.tcp = TCP(smb_packet)