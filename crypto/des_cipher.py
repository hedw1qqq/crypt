from interfaces import IKeySchedule, IRoundFunction
from feistel_cipher import FeistelCipher
from bitperm import bitperm
from utility import xor_bytes

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
        if len(master_key) != 8:
            raise ValueError("DES key must be 8 bytes (64 bits)")

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


class DESRoundFunction(IRoundFunction):
    # fmt: off
    EXPANSION = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    SBOXES = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    P = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]
    # fmt: on
    def apply(self, half_block: bytes, round_key: bytes) -> bytes:
        """f(R, K) = P(S(E(R) XOR K))."""
        if len(half_block) != 4:
            raise ValueError("Half block must be 4 bytes")
        if len(round_key) != 6:
            raise ValueError("Round key must be 6 bytes")
        expanded = bitperm(
            half_block, self.EXPANSION, msb_first=True, one_based_indexing=True
        )
        xored = xor_bytes(expanded, round_key)
        substituted = self._apply_sboxes(xored)
        result = bitperm(substituted, self.P, msb_first=True, one_based_indexing=True)
        return result

    def _apply_sboxes(self, data: bytes) -> bytes:
        if len(data) != 6:
            raise ValueError("Data must be 6 bytes")

        bits = int.from_bytes(data, "big")
        result = 0

        for i in range(8):
            sbox_input = (bits >> (42 - i * 6)) & 0b111111
            bit_5 = (sbox_input & 0b100000) >> 4
            bit_0 = sbox_input & 0b000001
            row = bit_5 | bit_0
            col = (sbox_input >> 1) & 0b001111  # средние 4 бита
            sbox_value = self.SBOXES[i][row][col]
            result = (result << 4) | sbox_value

        return result.to_bytes(4, "big")


class DES(FeistelCipher):
    # fmt: off
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # FP
    FP = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    # fmt: on
    def __init__(self):
        key_schedule = DESKeySchedule()
        round_function = DESRoundFunction()

        super().__init__(
            key_schedule=key_schedule,
            round_function=round_function,
            block_size=8,
            num_rounds=16,
        )

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Алгоритм:
        1. IP
        2. 16 раундов Фейстеля
        3. Swap: R16L16
        4. FP
        """
        if len(block) != 8:
            raise ValueError("Block must be 8 bytes (64 bits)")
        permuted = bitperm(block, self.IP, msb_first=True, one_based_indexing=True)
        feistel_output = super().encrypt_block(permuted)
        L16 = feistel_output[:4]
        R16 = feistel_output[4:]
        preoutput = R16 + L16

        ciphertext = bitperm(
            preoutput, self.FP, msb_first=True, one_based_indexing=True
        )

        return ciphertext

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("Block must be 8 bytes (64 bits)")

        permuted = bitperm(block, self.IP, msb_first=True, one_based_indexing=True)
        feistel_output = super().decrypt_block(permuted)

        L16 = feistel_output[:4]
        R16 = feistel_output[4:]
        preoutput = R16 + L16

        plaintext = bitperm(preoutput, self.FP, msb_first=True, one_based_indexing=True)

        return plaintext
