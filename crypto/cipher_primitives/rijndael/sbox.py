from crypto.services.galois_service import GField


class SBox:
    def __init__(self, mod_poly: int):
        self.mod_poly = mod_poly
        self._forward = None
        self._inverse = None

    def _initialize(self):
        if self._forward is not None:
            return

        self._forward = bytearray(256)
        self._inverse = bytearray(256)

        for i in range(256):

            b = 0 if i == 0 else GField.inverse(i, self.mod_poly)

            s = b
            s ^= ((b << 1) | (b >> 7)) & 0xFF
            s ^= ((b << 2) | (b >> 6)) & 0xFF
            s ^= ((b << 3) | (b >> 5)) & 0xFF
            s ^= ((b << 4) | (b >> 4)) & 0xFF
            s ^= 0x63

            self._forward[i] = s

        for s in range(256):

            val = s

            b = ((val << 1) | (val >> 7)) & 0xFF
            b ^= ((val << 3) | (val >> 5)) & 0xFF
            b ^= ((val << 6) | (val >> 2)) & 0xFF
            b ^= 0x05

            inv_b = 0 if b == 0 else GField.inverse(b, self.mod_poly)

            self._inverse[s] = inv_b

    def sub(self, val: int) -> int:
        self._initialize()
        return self._forward[val]

    def inv_sub(self, val: int) -> int:
        self._initialize()
        return self._inverse[val]
