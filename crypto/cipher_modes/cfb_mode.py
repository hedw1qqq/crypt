import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import split_blocks, xor_bytes


class CFBMode(BaseCipherMode):
    """CFB: C_i = P_i XOR E_K(C_{i-1})"""

    def _worker_encrypt(self, block: bytes):

        return self.primitive.encrypt_block(block)

    def encrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)

        full_blocks_count = len(data) // bs
        full_blocks = data[: full_blocks_count * bs]
        tail = data[full_blocks_count * bs :]

        prev_cipher = iv
        output = [iv]

        for block in split_blocks(full_blocks, bs):
            s = self.primitive.encrypt_block(prev_cipher)
            cipher_block = xor_bytes(block, s)
            output.append(cipher_block)
            prev_cipher = cipher_block

        if tail:
            s = self.primitive.encrypt_block(prev_cipher)
            cipher_tail = xor_bytes(tail, s[: len(tail)])
            output.append(cipher_tail)

        return b"".join(output)

    def decrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size

        if len(data) < bs:
            raise ValueError("Ciphertext too short for CFB mode")

        iv = data[:bs]
        ciphertext = data[bs:]

        if not ciphertext:
            return b""

        full_blocks_count = len(ciphertext) // bs
        full_blocks = ciphertext[: full_blocks_count * bs]
        tail = ciphertext[full_blocks_count * bs :]

        output = []

        if full_blocks:
            cipher_blocks = list(split_blocks(full_blocks, bs))
            inputs = [iv] + cipher_blocks[:-1]

            keystreams = list(self._executor.map(self._worker_encrypt, inputs))
            plaintexts = [xor_bytes(c, ks) for c, ks in zip(cipher_blocks, keystreams)]
            output.extend(plaintexts)
            prev_cipher = cipher_blocks[-1]
        else:
            prev_cipher = iv

        if tail:
            s = self.primitive.encrypt_block(prev_cipher)
            plain_tail = xor_bytes(tail, s[: len(tail)])
            output.append(plain_tail)

        return b"".join(output)

    def encrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)
        fout.write(iv)
        prev_cipher = iv
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for block in split_blocks(full, bs):
                s = self.primitive.encrypt_block(prev_cipher)
                output = xor_bytes(block, s)
                fout.write(output)
                prev_cipher = output

        if carry:
            s = self.primitive.encrypt_block(prev_cipher)
            fout.write(xor_bytes(carry, s[: len(carry)]))

    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for CFB mode")

        carry = b""
        prev_cipher = iv

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            if full:
                cipher_blocks = list(split_blocks(full, bs))
                inputs = [prev_cipher] + cipher_blocks[:-1]

                keystreams = list(self._executor.map(self._worker_encrypt, inputs))
                plaintexts = [
                    xor_bytes(c, ks) for c, ks in zip(cipher_blocks, keystreams)
                ]
                fout.write(b"".join(plaintexts))
                prev_cipher = cipher_blocks[-1]

        if carry:
            s = self.primitive.encrypt_block(prev_cipher)
            fout.write(xor_bytes(carry, s[: len(carry)]))
