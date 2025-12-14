from typing import List

from crypto.cipher_primitives.rc5.rc5_utils import RC5Utils
from crypto.utility.interfaces import IKeySchedule


class RC5KeySchedule(IKeySchedule):
    def __init__(self, w: int, r: int):
        if w not in (16, 32, 64):
            raise ValueError("word size must be 16, 32 or 64")
        self.w = w
        self.r = r
        self.u = w // 8

    def expand_key(self, master_key: bytes) -> List[bytes]:
        w = self.w
        u = self.u
        b = len(master_key)
        mask = (1 << w) - 1

        c = max(1, (b + u - 1) // u)
        L = [0] * c
        for i in range(b - 1, -1, -1):
            L[i // u] = ((L[i // u] << 8) + master_key[i]) & mask

        #  Инициализация массива S константами P и Q
        t = 2 * (self.r + 1)
        S = [0] * t
        P, Q = RC5Utils.calc_PQ(w)
        S[0] = P
        for i in range(1, t):
            S[i] = (S[i - 1] + Q) & mask

        # Смешивание S и L
        i = j = 0
        A = B = 0
        for _ in range(3 * max(t, c)):
            A = S[i] = RC5Utils.rotl((S[i] + A + B) & mask, 3, w)
            B = L[j] = RC5Utils.rotl((L[j] + A + B) & mask, (A + B), w)
            i = (i + 1) % t
            j = (j + 1) % c

        # Возвращаем как list[bytes] согласно интерфейсу
        return [RC5Utils.word_to_bytes_le(val, u) for val in S]
