import asyncio
from modes import PaddingMode, CipherMode
from utility import xor_bytes, split_blocks, pad, unpad
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
        self.block_size = getattr(primitive, "block_size", None)
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

    # CBC: C_i = E(P_i XOR C_{i-1}), C_0 = E(P_0 XOR IV)
    def _encrypt_cbc(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = split_blocks(padded, self.block_size)
        prev = iv
        out = []
        for block in blocks:
            x = xor_bytes(block, prev)
            c = self.primitive.encrypt_block(x)
            out.append(c)
            prev = c
        return iv + b''.join(out)

    def _decrypt_cbc(self, data: bytes) -> bytes:
        iv = data[:self.block_size]
        blocks = split_blocks(data[self.block_size:], self.block_size)
        prev = iv
        out = []
        for c in blocks:
            x = self.primitive.decrypt_block(c)
            p = xor_bytes(x, prev)
            out.append(p)
            prev = c
        return unpad(b''.join(out), self.block_size, self.padding)
