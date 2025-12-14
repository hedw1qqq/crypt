import math


class RC5Utils:
    @staticmethod
    def rotl(x: int, y: int, w: int) -> int:
        mask = (1 << w) - 1
        y %= w
        return ((x << y) | (x >> (w - y))) & mask

    @staticmethod
    def rotr(x: int, y: int, w: int) -> int:
        mask = (1 << w) - 1
        y %= w
        return ((x >> y) | (x << (w - y))) & mask

    @staticmethod
    def calc_PQ(w: int) -> tuple[int, int]:
        """
        P_w = Odd((e - 2) * 2^w)
        Q_w = Odd((φ - 1) * 2^w)
        """
        e = math.e
        phi = (1 + math.sqrt(5)) / 2

        P = int((e - 2) * (2 ** w))
        Q = int((phi - 1) * (2 ** w))

        if P % 2 == 0:
            P += 1
        if Q % 2 == 0:
            Q += 1

        mask = (1 << w) - 1
        return P & mask, Q & mask

    @staticmethod
    def bytes_to_word_le(b: bytes) -> int:
        """Интерпретировать bytes как little-endian слово."""
        x = 0
        for i, v in enumerate(b):
            x |= v << (8 * i)
        return x

    @staticmethod
    def word_to_bytes_le(x: int, length: int) -> bytes:
        """Преобразовать слово в little-endian bytes фиксированной длины."""
        return bytes((x >> (8 * i)) & 0xFF for i in range(length))
