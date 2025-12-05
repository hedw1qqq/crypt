from crypto.cipher_primitives.rijndael.sbox import SBox
from crypto.cipher_primitives.rijndael.rijndael_key_schedule import (
    RijndaelKeyScheduler,
    calculate_num_rounds,
)
from crypto.cipher_primitives.rijndael.rijndael_round_func import (
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key,
)
from crypto.utility.interfaces import ISymmetricCipher


class RijndaelCipher(ISymmetricCipher):
    def __init__(
        self, block_size: int, key_size: int, mod_poly: int = 0x11B, mode=None
    ):
        if block_size not in (16, 24, 32):
            raise ValueError(f"Invalid block size: {block_size}")
        if key_size not in (16, 24, 32):
            raise ValueError(f"Invalid key size: {key_size}")

        self.block_size = block_size
        self.key_size = key_size
        self.mod_poly = mod_poly

        self.num_rounds = calculate_num_rounds(block_size, key_size)

        self.round_keys = None
        self.sbox = None

    def setup_keys(self, key: bytes):
        if len(key) != self.key_size:
            raise ValueError(
                f"Key size mismatch: expected {self.key_size}, got {len(key)}"
            )

        if self.sbox is None:
            self.sbox = SBox(self.mod_poly)

        keygen = RijndaelKeyScheduler(
            self.block_size, self.key_size, self.sbox, self.mod_poly
        )
        self.round_keys = keygen.expand_key(key)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != self.block_size:
            raise ValueError(
                f"Block size mismatch: expected {self.block_size}, got {len(plaintext)}"
            )
        if self.round_keys is None or self.sbox is None:
            raise ValueError("Key not set")

        round_keys = self.round_keys
        sbox = self.sbox

        nb = self.block_size // 4

        # bytes -> state (column-major)
        state = [bytearray(nb) for _ in range(4)]
        for i in range(4):
            for j in range(nb):
                state[i][j] = plaintext[j * 4 + i]

        state = add_round_key(state, round_keys[0])

        for r in range(1, self.num_rounds):
            state = sub_bytes(state, sbox, False)
            state = shift_rows(state, False)
            state = mix_columns(state, self.mod_poly, False)
            state = add_round_key(state, round_keys[r])

        state = sub_bytes(state, sbox, False)
        state = shift_rows(state, False)
        state = add_round_key(state, round_keys[self.num_rounds])

        # state -> bytes
        ciphertext = bytearray(self.block_size)
        for i in range(4):
            for j in range(nb):
                ciphertext[j * 4 + i] = state[i][j]

        return bytes(ciphertext)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != self.block_size:
            raise ValueError(
                f"Block size mismatch: expected {self.block_size}, got {len(ciphertext)}"
            )
        if self.round_keys is None or self.sbox is None:
            raise ValueError("Key not set")

        round_keys = self.round_keys
        sbox = self.sbox

        nb = self.block_size // 4

        state = [bytearray(nb) for _ in range(4)]
        for i in range(4):
            for j in range(nb):
                state[i][j] = ciphertext[j * 4 + i]

        state = add_round_key(state, round_keys[self.num_rounds])

        for r in range(self.num_rounds - 1, 0, -1):
            state = shift_rows(state, True)
            state = sub_bytes(state, sbox, True)
            state = add_round_key(state, round_keys[r])
            state = mix_columns(state, self.mod_poly, True)

        state = shift_rows(state, True)
        state = sub_bytes(state, sbox, True)
        state = add_round_key(state, round_keys[0])

        plaintext = bytearray(self.block_size)
        for i in range(4):
            for j in range(nb):
                plaintext[j * 4 + i] = state[i][j]

        return bytes(plaintext)
