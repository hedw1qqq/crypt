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
            val = i
            inv_val = 0 if val == 0 else GField.inverse(val, self.mod_poly)

            # Аффинное преобразование
            result = inv_val
            result ^= ((inv_val << 1) | (inv_val >> 7)) & 0xFF
            result ^= ((inv_val << 2) | (inv_val >> 6)) & 0xFF
            result ^= ((inv_val << 3) | (inv_val >> 5)) & 0xFF
            result ^= ((inv_val << 4) | (inv_val >> 4)) & 0xFF
            result ^= 0x63

            self._forward[i] = result

        for i in range(256):
            self._inverse[self._forward[i]] = i

    def sub(self, val: int) -> int:
        self._initialize()
        return self._forward[val]

    def inv_sub(self, val: int) -> int:
        self._initialize()
        return self._inverse[val]
