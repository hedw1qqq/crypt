"""RANDOM_DELTA Mode with parallelization"""

import secrets
from typing import BinaryIO
from .base_mode import BaseCipherMode
from crypto.utility.utility import pad, unpad, split_blocks, xor_bytes


class RandomDeltaMode(BaseCipherMode):
    """RANDOM_DELTA: C_i = E_K(P_i XOR C_{i-1}) XOR Δ_i"""

    def _worker_decrypt(self, block: bytes):
        prim = self._get_thread_primitive()
        return prim.decrypt_block(block)

    def encrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        padded = pad(data, bs, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(bs)

        prev_cipher = iv
        output_parts = [iv]

        for p_block in split_blocks(padded, bs):
            delta = secrets.token_bytes(bs)
            x_out = self.primitive.encrypt_block(xor_bytes(p_block, prev_cipher))
            c_block = xor_bytes(x_out, delta)
            output_parts.extend([delta, c_block])
            prev_cipher = c_block

        return b"".join(output_parts)

    def decrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        if len(data) < bs:
            raise ValueError("Ciphertext too short for RANDOM_DELTA mode")

        iv = data[:bs]
        ciphertext = data[bs:]

        if len(ciphertext) % (bs * 2) != 0:
            raise ValueError("Invalid ciphertext length for RANDOM_DELTA mode")

        combined_blocks = list(split_blocks(ciphertext, bs * 2))
        delta_cipher_pairs = [(c[:bs], c[bs:]) for c in combined_blocks]

        xor_blocks = [
            xor_bytes(c_block, delta) for delta, c_block in delta_cipher_pairs
        ]
        decrypted_xor = list(self._executor.map(self._worker_decrypt, xor_blocks))

        prev_cipher = iv
        plaintext_parts = []

        for i, dec_xor in enumerate(decrypted_xor):
            plaintext_parts.append(xor_bytes(dec_xor, prev_cipher))
            prev_cipher = delta_cipher_pairs[i][1]

        return unpad(b"".join(plaintext_parts), bs, self.padding)

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

            for p_block in split_blocks(full, bs):
                delta = secrets.token_bytes(bs)
                x_out = self.primitive.encrypt_block(xor_bytes(p_block, prev_cipher))
                c_block = xor_bytes(x_out, delta)
                fout.write(delta)
                fout.write(c_block)
                prev_cipher = c_block

        for p_block in split_blocks(pad(carry, bs, self.padding), bs):
            delta = secrets.token_bytes(bs)
            x_out = self.primitive.encrypt_block(xor_bytes(p_block, prev_cipher))
            c_block = xor_bytes(x_out, delta)
            fout.write(delta)
            fout.write(c_block)
            prev_cipher = c_block

    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for RANDOM_DELTA mode")

        prev_cipher = iv
        carry = b""
        hold = None

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // (bs * 2)) * (bs * 2)
            full, carry = data[:full_len], data[full_len:]

            if full:
                pairs = [
                    (full[i : i + bs], full[i + bs : i + bs * 2])
                    for i in range(0, len(full), bs * 2)
                ]

                xor_blocks = [xor_bytes(c_block, delta) for delta, c_block in pairs]
                decrypted = list(self._executor.map(self._worker_decrypt, xor_blocks))

                for i, dec_xor in enumerate(decrypted):
                    plaintext_block = xor_bytes(dec_xor, prev_cipher)

                    if hold is not None:
                        fout.write(hold)
                    hold = plaintext_block
                    prev_cipher = pairs[i][1]

        if carry:
            raise ValueError("Invalid ciphertext length for RANDOM_DELTA mode")

        if hold is not None:
            fout.write(unpad(hold, bs, self.padding))
