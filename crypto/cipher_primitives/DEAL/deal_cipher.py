from crypto.cipher_primitives.DEAL.DEALKeySchedule import DEALKeySchedule
from crypto.cipher_primitives.DEAL.deal_adapter import DESAdapter
from crypto.feistel.feistel_cipher import FeistelCipher


class DEAL(FeistelCipher):

    BLOCK_SIZE = 16

    def __init__(self, key_size: int = 128):
        if key_size not in (128, 192, 256):
            raise ValueError("Key size must be 128, 192, or 256 bits")

        self.key_size_bits = key_size
        self.num_rounds = 6 if key_size in (128, 192) else 8

        key_schedule = DEALKeySchedule(key_size_bits=key_size)
        round_function = DESAdapter()

        super().__init__(
            key_schedule=key_schedule,
            round_function=round_function,
            block_size=self.BLOCK_SIZE,
            num_rounds=self.num_rounds,
        )
