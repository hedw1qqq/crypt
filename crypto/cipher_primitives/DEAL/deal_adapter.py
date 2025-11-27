from crypto.utility.interfaces import IRoundFunction
from crypto.cipher_primitives.DES.des_cipher import DES


class DESAdapter(IRoundFunction):
    def apply(self, half_block: bytes, round_key: bytes) -> bytes:
        if len(half_block) != 8:
            raise ValueError("Half block must be 8 bytes for DEAL")
        if len(round_key) != 8:
            raise ValueError("Round key must be 8 bytes for DES")
        des = DES()
        des.setup_keys(round_key)
        return des.encrypt_block(half_block)
