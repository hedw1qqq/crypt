
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import pad, unpad, split_blocks


class ECBMode(BaseCipherMode):
    """ECB: C_i = E_K(P_i)"""

    def _worker_encrypt(self, block: bytes):
        prim = self._get_thread_primitive()
        return prim.encrypt_block(block)

    def _worker_decrypt(self, block: bytes):
        prim = self._get_thread_primitive()
        return prim.decrypt_block(block)

    def encrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        padded = pad(data, bs, self.padding)
        blocks = list(split_blocks(padded, bs))
        results = list(self._executor.map(self._worker_encrypt, blocks))
        return b"".join(results)

    def decrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        if len(data) % bs != 0:
            raise ValueError("Ciphertext length must be multiple of block size for ECB")
        blocks = list(split_blocks(data, bs))
        results = list(self._executor.map(self._worker_decrypt, blocks))
        return unpad(b"".join(results), bs, self.padding)

    def encrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            if full:
                blocks = list(split_blocks(full, bs))
                results = list(self._executor.map(self._worker_encrypt, blocks))
                fout.write(b"".join(results))

        padded = pad(carry, bs, self.padding)
        blocks = list(split_blocks(padded, bs))
        results = list(self._executor.map(self._worker_encrypt, blocks))
        fout.write(b"".join(results))

    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        carry = b""
        hold = None

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            if full:
                blocks = list(split_blocks(full, bs))
                results = list(self._executor.map(self._worker_decrypt, blocks))

                for block in results:
                    if hold is not None:
                        fout.write(hold)
                    hold = block

        if carry:
            raise ValueError("Ciphertext length must be multiple of block size for ECB")
        if hold is not None:
            fout.write(unpad(hold, bs, self.padding))
