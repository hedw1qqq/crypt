import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import split_blocks, xor_bytes


class OFBMode(BaseCipherMode):
    """OFB: S_i = E_K(S_{i-1}), C_i = P_i XOR S_i"""

    def encrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)

        full_blocks_count = len(data) // bs
        full_data = data[: full_blocks_count * bs]
        tail = data[full_blocks_count * bs :]

        prev_cipher = iv
        output = [iv]

        for block in split_blocks(full_data, bs):
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            output.append(xor_bytes(block, prev_cipher))

        if tail:
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            output.append(xor_bytes(tail, prev_cipher[: len(tail)]))

        return b"".join(output)

    def decrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size

        if len(data) < bs:
            raise ValueError("Ciphertext too short for OFB mode")

        iv = data[:bs]
        ciphertext = data[bs:]

        full_blocks_count = len(ciphertext) // bs
        full_data = ciphertext[: full_blocks_count * bs]
        tail = ciphertext[full_blocks_count * bs :]

        prev_cipher = iv
        output = []

        for block in split_blocks(full_data, bs):
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            output.append(xor_bytes(block, prev_cipher))

        if tail:
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            output.append(xor_bytes(tail, prev_cipher[: len(tail)]))

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
                prev_cipher = self.primitive.encrypt_block(prev_cipher)
                fout.write(xor_bytes(block, prev_cipher))

        if carry:
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            fout.write(xor_bytes(carry, prev_cipher[: len(carry)]))

    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for OFB mode")

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
                prev_cipher = self.primitive.encrypt_block(prev_cipher)
                fout.write(xor_bytes(block, prev_cipher))

        if carry:
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            fout.write(xor_bytes(carry, prev_cipher[: len(carry)]))
