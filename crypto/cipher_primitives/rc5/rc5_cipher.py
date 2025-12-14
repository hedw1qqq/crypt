from typing import List

from crypto.cipher_primitives.rc5.rc5_key_schedule import RC5KeySchedule
from crypto.cipher_primitives.rc5.rc5_utils import RC5Utils
from crypto.utility.interfaces import ISymmetricCipher


class RC5(ISymmetricCipher):
    @staticmethod
    def _validate(word_size: int, num_rounds: int) -> None:
        if word_size not in (16, 32, 64):
            raise ValueError("word_size must be 16, 32 or 64")
        if num_rounds < 0 or num_rounds > 255:
            raise ValueError("num_rounds must be between 0 and 255")

    def __init__(self, word_size: int = 32, num_rounds: int = 12):
        RC5._validate(word_size, num_rounds)
        self.w = word_size
        self.r = num_rounds
        self.u = word_size // 8
        self.block_size = 2 * self.u
        self.mask = (1 << self.w) - 1

        self._key_schedule = RC5KeySchedule(self.w, self.r)
        self.S: List[int] = []

    def setup_keys(self, key: bytes) -> None:
        raw_keys = self._key_schedule.expand_key(key)
        # Конвертируем один раз из bytes в int для эффективности
        self.S = [RC5Utils.bytes_to_word_le(k) for k in raw_keys]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(f"Block size must be {self.block_size} bytes")
        if not self.S:
            raise RuntimeError("Keys not initialized. Call setup_keys() first.")

        # Разбиваем блок на два слова A и B
        A = RC5Utils.bytes_to_word_le(block[: self.u])
        B = RC5Utils.bytes_to_word_le(block[self.u :])

        # Начальное сложение с подключами
        A = (A + self.S[0]) & self.mask
        B = (B + self.S[1]) & self.mask

        # Раунды шифрования
        for i in range(1, self.r + 1):
            A = (RC5Utils.rotl(A ^ B, B, self.w) + self.S[2 * i]) & self.mask
            B = (RC5Utils.rotl(B ^ A, A, self.w) + self.S[2 * i + 1]) & self.mask

        # Собираем результат
        return RC5Utils.word_to_bytes_le(A, self.u) + RC5Utils.word_to_bytes_le(
            B, self.u
        )

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(f"Block size must be {self.block_size} bytes")
        if not self.S:
            raise RuntimeError("Keys not initialized. Call setup_keys() first.")

        # Разбиваем блок на два слова A и B
        A = RC5Utils.bytes_to_word_le(block[: self.u])
        B = RC5Utils.bytes_to_word_le(block[self.u :])

        for i in range(self.r, 0, -1):
            B = RC5Utils.rotr((B - self.S[2 * i + 1]) & self.mask, A, self.w) ^ A
            A = RC5Utils.rotr((A - self.S[2 * i]) & self.mask, B, self.w) ^ B

        B = (B - self.S[1]) & self.mask
        A = (A - self.S[0]) & self.mask

        return RC5Utils.word_to_bytes_le(A, self.u) + RC5Utils.word_to_bytes_le(
            B, self.u
        )
