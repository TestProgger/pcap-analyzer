class HTTP_SCAN_RESPONSE:
    def __init__(self, src : str , dst : str , scanner : str) -> None:
        self.src = src
        self.dst = dst
        self.scanner = scanner