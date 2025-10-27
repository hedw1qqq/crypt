import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import pad, unpad, split_blocks, xor_bytes


class CBCMode(BaseCipherMode):
    """CBC: C_i = E_K(P_i XOR C_{i-1})"""

    def _worker_decrypt(self, block: bytes):
        prim = self._get_thread_primitive()
        return prim.decrypt_block(block)

    def encrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        padded = pad(data, bs, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(bs)

        prev_cipher = iv
        ciphertext = [iv]

        for P_i in split_blocks(padded, bs):
            C_i = self.primitive.encrypt_block(xor_bytes(P_i, prev_cipher))
            ciphertext.append(C_i)
            prev_cipher = C_i

        return b"".join(ciphertext)

    def decrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        if len(data) < bs:
            raise ValueError("Ciphertext too short for CBC mode")

        iv = data[:bs]
        ciphertext_blocks = list(split_blocks(data[bs:], bs))

        if not ciphertext_blocks:
            return b""

        decrypted_blocks = list(
            self._executor.map(self._worker_decrypt, ciphertext_blocks)
        )

        prev_cipher = iv
        plaintext = []

        for i, dec_block in enumerate(decrypted_blocks):
            plaintext.append(xor_bytes(dec_block, prev_cipher))
            prev_cipher = ciphertext_blocks[i]

        return unpad(b"".join(plaintext), bs, self.padding)

    def encrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)
        fout.write(iv)
        prev_c = iv
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for p in split_blocks(full, bs):
                c = self.primitive.encrypt_block(xor_bytes(p, prev_c))
                fout.write(c)
                prev_c = c

        for p in split_blocks(pad(carry, bs, self.padding), bs):
            c = self.primitive.encrypt_block(xor_bytes(p, prev_c))
            fout.write(c)
            prev_c = c

    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for CBC mode")

        prev_c = iv
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

                decrypted = list(self._executor.map(self._worker_decrypt, blocks))

                for i, dec_block in enumerate(decrypted):
                    plaintext_block = xor_bytes(dec_block, prev_c)

                    if hold is not None:
                        fout.write(hold)
                    hold = plaintext_block
                    prev_c = blocks[i]

        if carry:
            raise ValueError("Ciphertext length invalid for CBC mode")

        if hold is not None:
            fout.write(unpad(hold, bs, self.padding))
