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
        if hasattr(self.primitive, "setup_keys"):
            self.primitive.setup_keys(key)
        self._executor = ThreadPoolExecutor(max_workers=max_workers or (os.cpu_count() or 4))

    async def encrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._encrypt_sync, data)

    async def decrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._decrypt_sync, data)

    async def encrypt_file(self, input_path: str, output_path: str):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._encrypt_file_sync, input_path, output_path)
        print(f"File encrypted successfully: {input_path} -> {output_path}")

    async def decrypt_file(self, input_path: str, output_path: str):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._decrypt_file_sync, input_path, output_path)
        print(f"File decrypted successfully: {input_path} -> {output_path}")

    def _encrypt_file_sync(self, input_path: str, output_path: str):
        try:
            with open(input_path, 'rb') as f_in:
                plaintext = f_in.read()

            ciphertext = self._encrypt_sync(plaintext)

            with open(output_path, 'wb') as f_out:
                f_out.write(ciphertext)
        except FileNotFoundError:
            print(f"Error: Input file not found at {input_path}")
        except Exception as e:
            print(f"An error occurred during file encryption: {e}")

    def _decrypt_file_sync(self, input_path: str, output_path: str):
        try:
            with open(input_path, 'rb') as f_in:
                ciphertext = f_in.read()
            plaintext = self._decrypt_sync(ciphertext)
            with open(output_path, 'wb') as f_out:
                f_out.write(plaintext)
        except FileNotFoundError:
            print(f"Error: Input file not found at {input_path}")
        except Exception as e:
            print(f"An error occurred during file decryption: {e}")

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
        blocks = split_blocks(data[self.block_size:], self.block_size)
        prev_cipher = iv
        out = []
        for C_i in blocks:
            S_i = self.primitive.encrypt_block(prev_cipher)
            P_i = xor_bytes(C_i, S_i)
            out.append(P_i)
            prev_cipher = C_i
        return unpad(b''.join(out), self.block_size, self.padding)

    def _encrypt_ofb(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        S_prev = iv
        blocks = split_blocks(padded, self.block_size)
        out = []
        for P_i in blocks:
            S_i = self.primitive.encrypt_block(S_prev)
            c = xor_bytes(P_i, S_i)
            out.append(c)
            S_prev = S_i
        return iv + b''.join(out)

    def _decrypt_ofb(self, data: bytes) -> bytes:
        if len(data) < self.block_size or len(data) % self.block_size != 0:
            raise ValueError("Invalid ciphertext length for OFB")
        iv = data[:self.block_size]
        blocks = split_blocks(data[self.block_size:], self.block_size)
        S_prev = iv
        out = []
        for C_i in blocks:
            S_i = self.primitive.encrypt_block(S_prev)
            p = xor_bytes(C_i, S_i)
            out.append(p)
            S_prev = S_i
        return unpad(b''.join(out), self.block_size, self.padding)

    def _encrypt_ctr(self, data: bytes) -> bytes:
        # C_j = P_j XOR E_K(T_j)
        nonce = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = split_blocks(data, self.block_size)
        initial_counter = int.from_bytes(nonce, byteorder='big')

        def process_block(args):
            j, P_j = args
            # T_j = nonce || counter
            # mod 2^(block_size*8)
            T_j = ((initial_counter + j) % (2 ** (self.block_size * 8))).to_bytes(
                self.block_size, byteorder='big'
            )
            # O_j = C(T_j)
            O_j = self.primitive.encrypt_block(T_j)
            # C_j = P_j XOR O_j (для последнего блока берем только нужную длину)
            return xor_bytes(P_j, O_j[:len(P_j)])

        results = list(self._executor.map(process_block, enumerate(blocks)))
        return nonce + b''.join(results)

    def _decrypt_ctr(self, data: bytes) -> bytes:
        #  P_j = C_j XOR E_K(T_j)

        if len(data) < self.block_size:
            raise ValueError("Ciphertext too short for CTR mode")

        nonce = data[:self.block_size]
        ciphertext = data[self.block_size:]
        blocks = split_blocks(ciphertext, self.block_size)

        initial_counter = int.from_bytes(nonce, byteorder='big')

        def process_block(args):
            j, C_j = args
            # T_j = nonce || counter
            T_j = ((initial_counter + j) % (2 ** (self.block_size * 8))).to_bytes(
                self.block_size, byteorder='big'
            )
            # O_j = C(T_j)
            O_j = self.primitive.encrypt_block(T_j)
            # P_j = C_j XOR O_j
            return xor_bytes(C_j, O_j[:len(C_j)])

        results = list(self._executor.map(process_block, enumerate(blocks)))
        return b''.join(results)
