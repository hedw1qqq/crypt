from interfaces import ISymmetricCipher, IKeySchedule, IRoundFunction
from utility import xor_bytes


class FeistelCipher(ISymmetricCipher):
    def __init__(self,
                 key_schedule: IKeySchedule,
                 round_function: IRoundFunction,
                 block_size: int = 8,
                 num_rounds: int = 16):
        if block_size % 2 != 0:
            raise ValueError("Block size must be even")
        self.key_schedule = key_schedule
        self.round_function = round_function
        self.block_size = block_size
        self.num_rounds = num_rounds
        self.round_keys = []

    def setup_keys(self, key: bytes) -> None:
        self.round_keys = self.key_schedule.expand_key(key)
        if len(self.round_keys) < self.num_rounds:
            raise ValueError(
                f"Key schedule must generate at least {self.num_rounds} round keys, "
                f"but generated {len(self.round_keys)}"
            )

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Формула: L_{i+1} = R_i, R_{i+1} = L_i ⊕ F(R_i, K_i)
        """
        if len(block) != self.block_size:
            raise ValueError(f"Block size must be {self.block_size} bytes")
        half_size = self.block_size // 2
        L = block[:half_size]
        R = block[half_size:]
        for i in range(self.num_rounds):
            L_old = L
            L = R
            R = xor_bytes(L_old, self.round_function.apply(R, self.round_keys[i]))
        return L + R

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(f"Block size must be {self.block_size} bytes")
        half_size = self.block_size // 2
        L = block[:half_size]
        R = block[half_size:]

        for i in range(self.num_rounds - 1, -1, -1):
            L_old = L
            L = R
            R = xor_bytes(L_old, self.round_function.apply(L, self.round_keys[i]))

        return L + R
