import secrets
from typing import BinaryIO, Tuple
from .base_mode import BaseCipherMode
from crypto.utility.utility import split_blocks, xor_bytes


class CTRMode(BaseCipherMode):
    """CTR: T_j = Nonce || Counter_j, O_j = E_K(T_j), C_j = P_j XOR O_j"""

    def _worker_ctr(self, args: Tuple[bytes, int]):
        nonce, counter = args
        counter_bytes = counter.to_bytes(self.block_size // 2, "big")
        return self.primitive.encrypt_block(nonce + counter_bytes)

    def encrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size
        nonce = self.iv if self.iv else secrets.token_bytes(bs // 2)

        full_blocks_count = len(data) // bs
        full_data = data[: full_blocks_count * bs]
        tail = data[full_blocks_count * bs :]

        blocks = list(split_blocks(full_data, bs))

        counters = [(nonce, i) for i in range(len(blocks))]
        keystreams = list(self._executor.map(self._worker_ctr, counters))
        output = [nonce] + [
            xor_bytes(block, ks) for block, ks in zip(blocks, keystreams)
        ]

        if tail:
            counter_bytes = len(blocks).to_bytes(bs // 2, "big")
            O_j = self.primitive.encrypt_block(nonce + counter_bytes)
            output.append(xor_bytes(tail, O_j[: len(tail)]))

        return b"".join(output)

    def decrypt_bytes(self, data: bytes) -> bytes:
        bs = self.block_size

        if len(data) < bs // 2:
            raise ValueError("Ciphertext too short for CTR mode")

        nonce = data[: bs // 2]
        ciphertext = data[bs // 2 :]

        full_blocks_count = len(ciphertext) // bs
        full_data = ciphertext[: full_blocks_count * bs]
        tail = ciphertext[full_blocks_count * bs :]

        blocks = list(split_blocks(full_data, bs))

        counters = [(nonce, i) for i in range(len(blocks))]
        keystreams = list(self._executor.map(self._worker_ctr, counters))
        output = [xor_bytes(block, ks) for block, ks in zip(blocks, keystreams)]

        if tail:
            counter_bytes = len(blocks).to_bytes(bs // 2, "big")
            O_j = self.primitive.encrypt_block(nonce + counter_bytes)
            output.append(xor_bytes(tail, O_j[: len(tail)]))

        return b"".join(output)

    def encrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        nonce = self.iv if self.iv else secrets.token_bytes(bs // 2)
        fout.write(nonce)

        counter = 0
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

                counters = [(nonce, counter + i) for i in range(len(blocks))]
                keystreams = list(self._executor.map(self._worker_ctr, counters))

                for block, ks in zip(blocks, keystreams):
                    fout.write(xor_bytes(block, ks))

                counter += len(blocks)

        if carry:
            cnt_bytes = counter.to_bytes(bs // 2, "big")
            ks = self.primitive.encrypt_block(nonce + cnt_bytes)
            fout.write(xor_bytes(carry, ks[: len(carry)]))

    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        bs = self.block_size
        nonce = fin.read(bs // 2)
        if len(nonce) != bs // 2:
            raise ValueError("Ciphertext too short for CTR")

        counter = 0
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

                counters = [(nonce, counter + i) for i in range(len(blocks))]
                keystreams = list(self._executor.map(self._worker_ctr, counters))

                for block, ks in zip(blocks, keystreams):
                    fout.write(xor_bytes(block, ks))

                counter += len(blocks)

        if carry:
            cnt_bytes = counter.to_bytes(bs // 2, "big")
            ks = self.primitive.encrypt_block(nonce + cnt_bytes)
            fout.write(xor_bytes(carry, ks[: len(carry)]))
