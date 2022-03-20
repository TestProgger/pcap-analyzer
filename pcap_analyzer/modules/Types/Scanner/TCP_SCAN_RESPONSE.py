class TCP_SCAN_RESPONSE:
    def __init__(self , src , dst , ports : list[int]) -> None:
        self.src = src
        self.dst = dst
        self.ports = ports