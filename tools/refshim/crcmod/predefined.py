class Crc:
    digest_size = 2

    def __init__(self, name):
        if name != "xmodem":
            raise NotImplementedError(name)
        self.crc = 0

    def new(self, data=b""):
        c = Crc("xmodem")
        c.update(data)
        return c

    def update(self, data):
        crc = self.crc
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        self.crc = crc

    def digest(self):
        return self.crc.to_bytes(2, "big")

    def hexdigest(self):
        return self.digest().hex().upper()
