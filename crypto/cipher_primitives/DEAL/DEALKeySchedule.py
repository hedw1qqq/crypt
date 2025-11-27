from crypto.cipher_primitives.DES.des_cipher import DES
from crypto.utility.interfaces import IKeySchedule
from crypto.utility.utility import xor_bytes


class DEALKeySchedule(IKeySchedule):
    DEAL_CONSTANT_KEY = bytes.fromhex("1234567890abcdef")

    def __init__(self, key_size_bits: int = 128):
        if key_size_bits not in (128, 192, 256):
            raise ValueError("Key size must be 128, 192, or 256 bits")

        self.key_size_bits = key_size_bits
        self.key_size_bytes = key_size_bits // 8
        self.num_rounds = 6 if key_size_bits in (128, 192) else 8
        self.num_key_blocks = key_size_bits // 64

    def _make_bit_mask(self, bit_position: int) -> bytes:
        if bit_position < 1 or bit_position > 64:
            raise ValueError("Bit position must be between 1 and 64")

        mask_int = 1 << (64 - bit_position)  # бит 1 = MSB
        return mask_int.to_bytes(8, byteorder="big")

    def expand_key(self, master_key: bytes) -> list[bytes]:

        if len(master_key) != self.key_size_bytes:
            raise ValueError(
                f"Master key must be {self.key_size_bytes} bytes "
                f"for {self.key_size_bits}-bit DEAL"
            )

        key_blocks = [master_key[i : i + 8] for i in range(0, len(master_key), 8)]
        des = DES()
        des.setup_keys(self.DEAL_CONSTANT_KEY)

        def E(X: bytes) -> bytes:
            return des.encrypt_block(X)

        rks: list[bytes] = []

        if self.key_size_bits == 128:
            K1, K2 = key_blocks
            RK1 = E(K1)
            rks.append(RK1)

            RK2 = E(xor_bytes(K2, RK1))
            rks.append(RK2)

            RK3 = E(xor_bytes(xor_bytes(K1, self._make_bit_mask(1)), RK2))
            rks.append(RK3)

            RK4 = E(xor_bytes(xor_bytes(K2, self._make_bit_mask(2)), RK3))
            rks.append(RK4)

            RK5 = E(xor_bytes(xor_bytes(K1, self._make_bit_mask(4)), RK4))
            rks.append(RK5)

            RK6 = E(xor_bytes(xor_bytes(K2, self._make_bit_mask(8)), RK5))
            rks.append(RK6)

        elif self.key_size_bits == 192:
            K1, K2, K3 = key_blocks
            RK1 = E(K1)
            rks.append(RK1)

            RK2 = E(xor_bytes(K2, RK1))
            rks.append(RK2)

            RK3 = E(xor_bytes(xor_bytes(K1, self._make_bit_mask(1)), RK2))
            rks.append(RK3)

            RK4 = E(xor_bytes(xor_bytes(K2, self._make_bit_mask(1)), RK3))
            rks.append(RK4)

            RK5 = E(xor_bytes(xor_bytes(K1, self._make_bit_mask(2)), RK4))
            rks.append(RK5)

            RK6 = E(xor_bytes(xor_bytes(K3, self._make_bit_mask(4)), RK5))
            rks.append(RK6)

        elif self.key_size_bits == 256:
            K1, K2, K3, K4 = key_blocks
            RK1 = E(K1)
            rks.append(RK1)

            RK2 = E(xor_bytes(K2, RK1))
            rks.append(RK2)

            RK3 = E(xor_bytes(K3, RK2))
            rks.append(RK3)

            RK4 = E(xor_bytes(K4, RK3))
            rks.append(RK4)

            RK5 = E(xor_bytes(xor_bytes(K1, self._make_bit_mask(1)), RK4))
            rks.append(RK5)

            RK6 = E(xor_bytes(xor_bytes(K2, self._make_bit_mask(2)), RK5))
            rks.append(RK6)

            RK7 = E(xor_bytes(xor_bytes(K3, self._make_bit_mask(4)), RK6))
            rks.append(RK7)

            RK8 = E(xor_bytes(xor_bytes(K4, self._make_bit_mask(8)), RK7))
            rks.append(RK8)

        return rks
