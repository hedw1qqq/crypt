
from crypto.cipher_primitives.rijndael.sbox import SBox
from crypto.services.galois_service import GField
from crypto.utility.interfaces import IKeySchedule


def calculate_num_rounds(block_size: int, key_size: int) -> int:
    nb = block_size // 4
    nk = key_size // 4
    max_nk_nb = max(nk, nb)
    return max_nk_nb + 6

class RijndaelKeyScheduler(IKeySchedule):
    def __init__(self, block_size: int, key_size: int, sbox: SBox, mod_poly: int):
        self.block_size = block_size
        self.key_size = key_size
        self.sbox = sbox
        self.mod_poly = mod_poly

    def expand_key(self, key: bytes) -> list[bytes]:
        if len(key) != self.key_size:
            raise ValueError("Key size mismatch")

        nk = self.key_size // 4
        nb = self.block_size // 4
        nr = calculate_num_rounds(self.block_size, self.key_size)

        # w - массив слов (каждое слово - 4 байта)
        total_words = nb * (nr + 1)
        w = [bytearray(4) for _ in range(total_words)]

        for i in range(nk):
            w[i] = bytearray(key[4*i : 4*i+4])

        for i in range(nk, total_words):
            temp = bytearray(w[i-1])

            if i % nk == 0:
                temp = self._sub_word(self._rot_word(temp))
                rcon_val = self._rcon(i // nk)
                temp[0] ^= rcon_val
            elif nk > 6 and (i % nk == 4):
                temp = self._sub_word(temp)

            for j in range(4):
                w[i][j] = w[i-nk][j] ^ temp[j]

        round_keys = []
        for r in range(nr + 1):
            rk = bytearray(nb * 4)
            for c in range(nb):
                word = w[r * nb + c]
                for row in range(4):
                    rk[c*4 + row] = word[row]
            round_keys.append(bytes(rk))

        return round_keys

    def _rot_word(self, word: bytearray) -> bytearray:
        return bytearray([word[1], word[2], word[3], word[0]])

    def _sub_word(self, word: bytearray) -> bytearray:
        res = bytearray(4)
        for i in range(4):
            res[i] = self.sbox.sub(word[i])
        return res

    def _rcon(self, i: int) -> int:
        if i == 0:
            return 0
        val = 1
        for _ in range(1, i):
            val = GField.multiply(val, 0x02, self.mod_poly)
        return val