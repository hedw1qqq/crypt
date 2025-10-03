import asyncio
from modes import PaddingMode, CipherMode
from utility import xor_bytes, split_blocks, pad, unpad, swap
from typing import Optional, Tuple, Callable, Iterable
from concurrent.futures import ThreadPoolExecutor

import os
import math
import secrets
import hashlib


class SymmetricCipherContext:
    def __init__(self,
                 primitive,
                 key: bytes,
                 mode: CipherMode = CipherMode.ECB,
                 padding: PaddingMode = PaddingMode.PKCS7,
                 iv: Optional[bytes] = None,
                 max_workers: Optional[int] = None,
                 *mode_args):
        self.primitive = primitive
        self.key = key
        self.mode = mode
        self.padding = padding
        self.iv = iv
        self.mode_args = mode_args or ()
        self.block_size = getattr(primitive, "block_size")
        if self.block_size is None:
            raise ValueError("Primitive must have attribute block_size (bytes).")
        if hasattr(self.primitive, "set_key"):
            self.primitive.set_key(key)
        self._executor = ThreadPoolExecutor(max_workers=max_workers or (os.cpu_count() or 4))

    async def encrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._encrypt_sync, data)

    async def decrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._decrypt_sync, data)

    async def encrypt_file(self, input_path: str, output_path: str, chunk_size: int = 1024 * 1024):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._encrypt_file_sync, input_path, output_path, chunk_size)

    async def decrypt_file(self, input_path: str, output_path: str, chunk_size: int = 1024 * 1024):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._decrypt_file_sync, input_path, output_path, chunk_size)

    def _encrypt_sync(self, data: bytes) -> bytes:
        match self.mode:
            case CipherMode.ECB:
                return self._encrypt_ecb(data)
            case CipherMode.CBC:
                return self._encrypt_cbc(data)
            case CipherMode.PCBC:
                return self._encrypt_pcbc(data)
            case CipherMode.CFB:
                return self._encrypt_cfb(data)
            case CipherMode.OFB:
                return self._encrypt_ofb(data)
            case CipherMode.CTR:
                return self._encrypt_ctr(data)
            case CipherMode.RANDOM_DELTA:
                return self._encrypt_random_delta(data)
            case _:
                raise NotImplementedError(f"Mode {self.mode} not implemented")

    def _decrypt_sync(self, data: bytes) -> bytes:
        match self.mode:
            case CipherMode.ECB:
                return self._decrypt_ecb(data)
            case CipherMode.CBC:
                return self._decrypt_cbc(data)
            case CipherMode.PCBC:
                return self._decrypt_pcbc(data)
            case CipherMode.CFB:
                return self._decrypt_cfb(data)
            case CipherMode.OFB:
                return self._decrypt_ofb(data)
            case CipherMode.CTR:
                return self._decrypt_ctr(data)
            case CipherMode.RANDOM_DELTA:
                return self._decrypt_random_delta(data)
            case _:
                raise NotImplementedError(f"Mode {self.mode} not implemented")

    def _encrypt_ecb(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        blocks = split_blocks(padded, self.block_size)
        results = list(self._executor.map(self.primitive.encrypt_block, blocks))
        return b''.join(results)

    def _decrypt_ecb(self, data: bytes) -> bytes:
        if len(data) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size for ECB")
        blocks = split_blocks(data, self.block_size)
        results = list(self._executor.map(self.primitive.decrypt_block, blocks))
        joined = b"".join(results)
        return unpad(joined, self.block_size, self.padding)

    #   C_i = E(P_i XOR C_{i-1}),   C_0 = IV
    #   P_i = D(C_i) XOR C_{i-1}

    def _encrypt_cbc(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = split_blocks(padded, self.block_size)  # список P_i
        prev_cipher = iv
        ciphertext = []

        for P_i in blocks:
            x = xor_bytes(P_i, prev_cipher)
            C_i = self.primitive.encrypt_block(x)
            ciphertext.append(C_i)
            prev_cipher = C_i
        return iv + b''.join(ciphertext)

    def _decrypt_cbc(self, data: bytes) -> bytes:
        iv = data[:self.block_size]
        blocks = split_blocks(data[self.block_size:], self.block_size)  # список C_i
        prev_cipher = iv
        plaintext = []
        for C_i in blocks:
            x = self.primitive.decrypt_block(C_i)
            P_i = xor_bytes(x, prev_cipher)
            plaintext.append(P_i)
            prev_cipher = C_i

        return unpad(b''.join(plaintext), self.block_size, self.padding)

    #   C_i = E(P_i XOR P_{i-1} XOR C_{i-1}),   P_{-1}=0, C_0=IV
    #   P_i = D(C_i) XOR P_{i-1} XOR C_{i-1}

    def _encrypt_pcbc(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = split_blocks(padded, self.block_size)
        prev_cipher = iv
        prev_plain = b'\x00' * self.block_size
        ciphertext = []
        for P_i in blocks:
            x = xor_bytes(P_i, xor_bytes(prev_plain, prev_cipher))
            C_i = self.primitive.encrypt_block(x)
            ciphertext.append(C_i)
            prev_plain, prev_cipher = P_i, C_i
        return iv + b''.join(ciphertext)

    def _decrypt_pcbc(self, data: bytes) -> bytes:
        if len(data) < self.block_size or (len(data) - self.block_size) % self.block_size != 0:
            raise ValueError("Invalid ciphertext for PCBC")
        iv = data[:self.block_size]
        blocks = split_blocks(data[self.block_size:], self.block_size)  # C_i
        prev_cipher = iv
        prev_plain = b'\x00' * self.block_size
        plaintext = []
        for C_i in blocks:
            x = self.primitive.decrypt_block(C_i)
            P_i = xor_bytes(x, xor_bytes(prev_plain, prev_cipher))
            plaintext.append(P_i)
            prev_plain, prev_cipher = P_i, C_i

        return unpad(b''.join(plaintext), self.block_size, self.padding)

    #   C_i = P_i XOR E(C_{i-1}),   C_0 = P_0 XOR E(IV)
    #   P_i = C_i XOR E(C_{i-1})

    def _encrypt_cfb(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = split_blocks(padded, self.block_size)
        prev_cipher = iv
        ciphertext = []
        for P_i in blocks:
            S_i = self.primitive.encrypt_block(prev_cipher)
            C_i = xor_bytes(P_i, S_i)
            ciphertext.append(C_i)
            prev_cipher = C_i
        return iv + b''.join(ciphertext)

    def _decrypt_cfb(self, data: bytes) -> bytes:
        if len(data) < self.block_size or len(data) % self.block_size != 0:
            raise ValueError("Invalid ciphertext length for CFB")
        iv = data[:self.block_size]
        blocks = split_blocks(data[self.block_size:], self.block_size)  # C_i
        prev_cipher = iv
        plaintext = []
        for C_i in blocks:
            S_i = self.primitive.encrypt_block(prev_cipher)
            P_i = xor_bytes(C_i, S_i)
            plaintext.append(P_i)
            prev_cipher = C_i
        return unpad(b''.join(plaintext), self.block_size, self.padding)
