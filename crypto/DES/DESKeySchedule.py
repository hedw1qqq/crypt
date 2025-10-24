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

        key_64 = bytearray(8)
        bit_index = 0

        for byte_index in range(8):
            byte_val = 0
            for bit_pos in range(7):
                if bit_index // 8 < len(key_56):
                    source_byte = key_56[bit_index // 8]
                    source_bit = (source_byte >> (7 - (bit_index % 8))) & 1
                    byte_val |= source_bit << (7 - bit_pos)
                bit_index += 1

            ones_count = bin(byte_val).count("1")
            parity_bit = 1 if ones_count % 2 == 0 else 0
            byte_val = (byte_val << 1) | parity_bit

            key_64[byte_index] = byte_val & 0xFF

        return bytes(key_64)
