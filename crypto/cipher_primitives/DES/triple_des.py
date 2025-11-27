from crypto.utility.interfaces import ISymmetricCipher
from crypto.cipher_primitives.DES.des_cipher import DES


class TripleDES(ISymmetricCipher):
    block_size = 8

    def __init__(self, mode: str = "EDE") -> None:
        if mode not in ("EDE", "EEE"):
            raise ValueError("mode must be 'EDE' or 'EEE'")
        self.mode = mode
        self._des1 = DES()
        self._des2 = DES()
        self._des3 = DES()
        self._is_3key = False

    def setup_keys(self, key: bytes) -> None:
        n = len(key)
        if n not in (14, 16, 21, 24):
            raise ValueError("TripleDES key must be 14, 16, 21, or 24 bytes")

        if n in (21, 24):
            if n == 24:
                k1, k2, k3 = key[0:8], key[8:16], key[16:24]
            else:
                k1, k2, k3 = key[0:7], key[7:14], key[14:21]
            self._is_3key = True
        else:
            if n == 16:
                k1, k2 = key[0:8], key[8:16]
            else:
                k1, k2 = key[0:7], key[7:14]
            k3 = k1
            self._is_3key = False

        self._des1.setup_keys(k1)
        self._des2.setup_keys(k2)
        self._des3.setup_keys(k3)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("Block must be 8 bytes")
        if self.mode == "EDE":
            # EDE: E(K1) -> D(K2) -> E(K3)
            b1 = self._des1.encrypt_block(block)
            b2 = self._des2.decrypt_block(b1)
            b3 = self._des3.encrypt_block(b2)
        else:
            # EEE: E(K1) -> E(K2) -> E(K3)
            b1 = self._des1.encrypt_block(block)
            b2 = self._des2.encrypt_block(b1)
            b3 = self._des3.encrypt_block(b2)
        return b3

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("Block must be 8 bytes")
        if self.mode == "EDE":
            # inverse EDE: D(K3) -> E(K2) -> D(K1)
            b1 = self._des3.decrypt_block(block)
            b2 = self._des2.encrypt_block(b1)
            b3 = self._des1.decrypt_block(b2)
        else:
            # inverse EEE: D(K3) -> D(K2) -> D(K1)
            b1 = self._des3.decrypt_block(block)
            b2 = self._des2.decrypt_block(b1)
            b3 = self._des1.decrypt_block(b2)
        return b3
