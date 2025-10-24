from crypto.utility.interfaces import IKeySchedule
from crypto.utility.bitperm import bitperm
MASK_28_BITS = (1 << 28) - 1


class DESKeySchedule(IKeySchedule):
    # fmt: off
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]
    # fmt: on
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def expand_key(self, master_key: bytes) -> list[bytes]:
        if len(master_key) == 7:
            master_key = self._add_parity_bits(master_key)
        elif len(master_key) != 8:
            raise ValueError("DES key must be 7 bytes (56 bits) or 8 bytes (64 bits)")

        permuted_key = bitperm(
            master_key, self.PC1, msb_first=True, one_based_indexing=True
        )
        key_int = int.from_bytes(permuted_key, "big")
        C = (key_int >> 28) & MASK_28_BITS
        D = key_int & MASK_28_BITS
        round_keys = []

        for i in range(16):
            C = self._rotate_left_28(C, self.SHIFTS[i])
            D = self._rotate_left_28(D, self.SHIFTS[i])
            CD = ((C << 28) | D).to_bytes(7, "big")
            round_key = bitperm(CD, self.PC2, msb_first=True, one_based_indexing=True)
            round_keys.append(round_key)
        return round_keys

    def _rotate_left_28(self, value: int, shifts: int) -> int:
        return ((value << shifts) | (value >> (28 - shifts))) & MASK_28_BITS

    def _add_parity_bits(self, key_56: bytes) -> bytes:
        if len(key_56) != 7:
            raise ValueError("Key must be exactly 7 bytes")

        key_64 = bytearray()

        bit_string = "".join(format(byte, "08b") for byte in key_56)

        for i in range(0, 56, 7):
            seven_bits = bit_string[i : i + 7]
            ones_count = seven_bits.count("1")
            parity_bit = "1" if ones_count % 2 == 0 else "0"

            byte_with_parity = seven_bits + parity_bit
            key_64.append(int(byte_with_parity, 2))

        return bytes(key_64)
