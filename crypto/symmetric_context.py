import asyncio
from modes import PaddingMode, CipherMode
from utility import xor_bytes, split_blocks, pad, unpad
from typing import Optional
from concurrent.futures import ProcessPoolExecutor
import os
import secrets


def _encrypt_block_worker(args):
    block, primitive_class, key = args
    primitive = primitive_class()
    primitive.setup_keys(key)
    return primitive.encrypt_block(block)


def _decrypt_block_worker(args):
    block, primitive_class, key = args
    primitive = primitive_class()
    primitive.setup_keys(key)
    return primitive.decrypt_block(block)


def _ctr_encrypt_worker(args):
    nonce, counter, block_size, primitive_class, key = args
    primitive = primitive_class()
    primitive.setup_keys(key)
    counter_bytes = counter.to_bytes(block_size // 2, "big")
    t = nonce + counter_bytes
    return primitive.encrypt_block(t)


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
        self.primitive_class = type(primitive)
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

        self._executor = ProcessPoolExecutor(max_workers=max_workers or os.cpu_count())
        self._validate_iv()

    def _validate_iv(self):
        if self.mode in (CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB, CipherMode.OFB):
            if self.iv is not None and len(self.iv) != self.block_size:
                raise ValueError(f"IV must be {self.block_size} bytes for {self.mode.name} mode")
        elif self.mode == CipherMode.CTR:
            if self.iv is not None and len(self.iv) != self.block_size // 2:
                raise ValueError(f"IV (nonce) must be {self.block_size // 2} bytes for CTR mode")
        elif self.mode == CipherMode.RANDOM_DELTA:
            if self.iv is not None and len(self.iv) != self.block_size:
                raise ValueError(f"IV must be {self.block_size} bytes for RANDOM_DELTA mode")

    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=True)

    async def encrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._encrypt_sync, data)

    async def decrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._decrypt_sync, data)

    async def encrypt_file(self, input_path: str, output_path: str, chunk_size: int = 1024 * 1024) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._encrypt_file_stream, input_path, output_path, chunk_size)
        print(f"File encrypted successfully: {input_path} -> {output_path}")

    async def decrypt_file(self, input_path: str, output_path: str, chunk_size: int = 1024 * 1024) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._decrypt_file_stream, input_path, output_path, chunk_size)
        print(f"File decrypted successfully: {input_path} -> {output_path}")

    def _encrypt_file_stream(self, input_path: str, output_path: str, chunk_size: int) -> None:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            match self.mode:
                case CipherMode.ECB:
                    self._encrypt_file_ecb(fin, fout, chunk_size)
                case CipherMode.CBC:
                    self._encrypt_file_cbc(fin, fout, chunk_size)
                case CipherMode.PCBC:
                    self._encrypt_file_pcbc(fin, fout, chunk_size)
                case CipherMode.CFB:
                    self._encrypt_file_cfb(fin, fout, chunk_size)
                case CipherMode.OFB:
                    self._encrypt_file_ofb(fin, fout, chunk_size)
                case CipherMode.CTR:
                    self._encrypt_file_ctr(fin, fout, chunk_size)
                case CipherMode.RANDOM_DELTA:
                    self._encrypt_file_random_delta(fin, fout, chunk_size)
                case _:
                    raise NotImplementedError(f"Mode {self.mode} not implemented for file encryption")

    def _decrypt_file_stream(self, input_path: str, output_path: str, chunk_size: int) -> None:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            match self.mode:
                case CipherMode.ECB:
                    self._decrypt_file_ecb(fin, fout, chunk_size)
                case CipherMode.CBC:
                    self._decrypt_file_cbc(fin, fout, chunk_size)
                case CipherMode.PCBC:
                    self._decrypt_file_pcbc(fin, fout, chunk_size)
                case CipherMode.CFB:
                    self._decrypt_file_cfb(fin, fout, chunk_size)
                case CipherMode.OFB:
                    self._decrypt_file_ofb(fin, fout, chunk_size)
                case CipherMode.CTR:
                    self._decrypt_file_ctr(fin, fout, chunk_size)
                case CipherMode.RANDOM_DELTA:
                    self._decrypt_file_random_delta(fin, fout, chunk_size)
                case _:
                    raise NotImplementedError(f"Mode {self.mode} not implemented for file decryption")

    def _encrypt_file_ecb(self, fin, fout, chunk_size):
        """
        Формула: C_i = E_K(P_i)
        """
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
                args = [(block, self.primitive_class, self.key) for block in blocks]
                results = list(self._executor.map(_encrypt_block_worker, args))
                fout.write(b"".join(results))

        padded = pad(carry, bs, self.padding)
        blocks = list(split_blocks(padded, bs))
        args = [(block, self.primitive_class, self.key) for block in blocks]
        results = list(self._executor.map(_encrypt_block_worker, args))
        fout.write(b"".join(results))

    def _decrypt_file_ecb(self, fin, fout, chunk_size):
        """
        Формула: C_i = E_K(P_i)
        """
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

            blocks = list(split_blocks(full, bs))
            args = [(block, self.primitive_class, self.key) for block in blocks]
            dec_blocks = list(self._executor.map(_decrypt_block_worker, args))

            for block in dec_blocks:
                if hold is not None:
                    fout.write(hold)
                hold = block

        if carry:
            raise ValueError("Ciphertext length must be multiple of block size for ECB")
        if hold is not None:
            pt_last = unpad(hold, bs, self.padding)
            fout.write(pt_last)

    def _encrypt_file_cbc(self, fin, fout, chunk_size):
        """
        CBC (Cipher Block Chaining).
        Формулы:
        C_i = E_K(P_i XOR C_{i-1})
        C_0 = IV
        """

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
                x = xor_bytes(p, prev_c)
                c = self.primitive.encrypt_block(x)
                fout.write(c)
                prev_c = c

        padded = pad(carry, bs, self.padding)

        for p in split_blocks(padded, bs):
            x = xor_bytes(p, prev_c)
            c = self.primitive.encrypt_block(x)
            fout.write(c)
            prev_c = c

    def _decrypt_file_cbc(self, fin, fout, chunk_size):
        """
        CBC дешифрование.
        Формула: P_i = D_K(C_i) XOR C_{i-1}
        """
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

            for C_i in split_blocks(full, bs):
                x = self.primitive.decrypt_block(C_i)
                P_i = xor_bytes(x, prev_c)
                if hold is not None:
                    fout.write(hold)
                hold = P_i
                prev_c = C_i

        if carry:
            raise ValueError("Ciphertext length invalid for CBC mode")
        if hold is not None:
            pt_last = unpad(hold, bs, self.padding)
            fout.write(pt_last)

    def _encrypt_file_pcbc(self, fin, fout, chunk_size):
        """
        PCBC (Propagating Cipher Block Chaining).
        Формулы:
            C_i = E_K(P_i XOR P_{i-1} XOR C_{i-1})
            P_{-1} = 0, C_0 = IV
        """

        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)
        fout.write(iv)

        prev_c = iv
        prev_p = b"\x00" * bs
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for p in split_blocks(full, bs):
                x = xor_bytes(p, xor_bytes(prev_p, prev_c))
                c = self.primitive.encrypt_block(x)
                fout.write(c)
                prev_p, prev_c = p, c

        padded = pad(carry, bs, self.padding)

        for p in split_blocks(padded, bs):
            x = xor_bytes(p, xor_bytes(prev_p, prev_c))
            c = self.primitive.encrypt_block(x)
            fout.write(c)
            prev_p, prev_c = p, c

    def _decrypt_file_pcbc(self, fin, fout, chunk_size):
        """
        PCBC дешифрование.

        Формула: P_i = D_K(C_i) XOR P_{i-1} XOR C_{i-1}
        """
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for PCBC mode")

        prev_c = iv
        prev_p = b"\x00" * bs
        carry = b""
        hold = None

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for C_i in split_blocks(full, bs):
                x = self.primitive.decrypt_block(C_i)
                P_i = xor_bytes(x, xor_bytes(prev_p, prev_c))
                if hold is not None:
                    fout.write(hold)
                hold = P_i
                prev_p, prev_c = P_i, C_i

        if carry:
            raise ValueError("Ciphertext length invalid for PCBC mode")
        if hold is not None:
            pt_last = unpad(hold, bs, self.padding)
            fout.write(pt_last)

    def _encrypt_file_cfb(self, fin, fout, chunk_size):
        """
        CFB (Cipher Feedback)у.
        Формулы:
            C_i = P_i XOR E_K(C_{i-1})
            C_0 = IV.
        """
        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)
        fout.write(iv)

        state = iv
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for block in split_blocks(full, bs):
                s = self.primitive.encrypt_block(state)
                c = xor_bytes(block, s)
                fout.write(c)
                state = c

        if carry:
            s = self.primitive.encrypt_block(state)
            fout.write(xor_bytes(carry, s[:len(carry)]))

    def _decrypt_file_cfb(self, fin, fout, chunk_size):
        """
        CFB дешифрование.
        Формула: P_i = C_i XOR E_K(C_{i-1})
        """
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for CFB mode")

        prev = iv

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            for block in split_blocks(chunk, bs):
                s = self.primitive.encrypt_block(prev)
                p = xor_bytes(block, s[:len(block)])
                fout.write(p)
                if len(block) == bs:
                    prev = block

    def _encrypt_file_ofb(self, fin, fout, chunk_size):
        """
        OFB (Output Feedback)
        Формулы:
            S_i = E_K(S_{i-1})
            C_i = P_i XOR S_i
            S_0 = IV
        """
        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)
        fout.write(iv)

        state = iv
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for block in split_blocks(full, bs):
                state = self.primitive.encrypt_block(state)
                c = xor_bytes(block, state)
                fout.write(c)

        if carry:
            s = self.primitive.encrypt_block(state)
            fout.write(xor_bytes(carry, s[:len(carry)]))

    def _decrypt_file_ofb(self, fin, fout, chunk_size):
        """
        OFB дешифрование.

        Формула: P_i = C_i XOR S_i, где S_i = E_K(S_{i-1})
        """
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for OFB mode")

        s_prev = iv

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            for block in split_blocks(chunk, bs):
                s_prev = self.primitive.encrypt_block(s_prev)
                p = xor_bytes(block, s_prev[:len(block)])
                fout.write(p)

    def _encrypt_file_ctr(self, fin, fout, chunk_size):
        """
        CTR (Counter) - режим счётчика.

        Формулы:
            T_j = Nonce || Counter_j
            O_j = E_K(T_j)
            C_j = P_j XOR O_j
        """
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

            blocks = list(split_blocks(full, bs))
            counters = [counter + i for i in range(len(blocks))]
            args = [(nonce, cnt, bs, self.primitive_class, self.key) for cnt in counters]
            keystreams = list(self._executor.map(_ctr_encrypt_worker, args))

            for block, ks in zip(blocks, keystreams):
                fout.write(xor_bytes(block, ks))
            counter += len(blocks)

        if carry:
            cnt_bytes = counter.to_bytes(bs // 2, "big")
            t = nonce + cnt_bytes
            ks = self.primitive.encrypt_block(t)
            fout.write(xor_bytes(carry, ks[:len(carry)]))

    def _decrypt_file_ctr(self, fin, fout, chunk_size):
        """
        CTR дешифрование.

        Формула: P_j = C_j XOR O_j, где O_j = E_K(Nonce || Counter_j)
        """
        bs = self.block_size
        nonce = fin.read(bs // 2)
        if len(nonce) != bs // 2:
            raise ValueError("Ciphertext too short for CTR")

        counter = 0

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            blocks = list(split_blocks(chunk, bs))
            counters = [counter + i for i in range(len(blocks))]
            args = [(nonce, cnt, bs, self.primitive_class, self.key) for cnt in counters]
            keystreams = list(self._executor.map(_ctr_encrypt_worker, args))

            for block, ks in zip(blocks, keystreams):
                fout.write(xor_bytes(block, ks[:len(block)]))
            counter += len(blocks)

    def _encrypt_file_random_delta(self, fin, fout, chunk_size):
        """
        Формулы:
            C_i = E_K(P_i XOR C_{i-1}) XOR Δ_i
            C_0 = IV, Δ_i - случайные байты
        Выход: IV || Δ_1 || C_1 || Δ_2 || C_2 || ...
        """
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
                x_in = xor_bytes(p_block, prev_cipher)
                x_out = self.primitive.encrypt_block(x_in)
                c_block = xor_bytes(x_out, delta)
                fout.write(delta)
                fout.write(c_block)
                prev_cipher = c_block

        padded = pad(carry, bs, self.padding)
        for p_block in split_blocks(padded, bs):
            delta = secrets.token_bytes(bs)
            x_in = xor_bytes(p_block, prev_cipher)
            x_out = self.primitive.encrypt_block(x_in)
            c_block = xor_bytes(x_out, delta)
            fout.write(delta)
            fout.write(c_block)
            prev_cipher = c_block

    def _decrypt_file_random_delta(self, fin, fout, chunk_size):
        """
        Формула: P_i = D_K(C_i XOR Δ_i) XOR C_{i-1}
        """
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

            # delta + ciphertext
            full_len = (len(data) // (bs * 2)) * (bs * 2)
            full, carry = data[:full_len], data[full_len:]

            for combined in split_blocks(full, bs * 2):
                delta = combined[:bs]
                c_block = combined[bs:]

                x_out = xor_bytes(c_block, delta)
                x_in = self.primitive.decrypt_block(x_out)
                p_block = xor_bytes(x_in, prev_cipher)

                if hold is not None:
                    fout.write(hold)
                hold = p_block
                prev_cipher = c_block

        if carry:
            raise ValueError("Invalid ciphertext length for RANDOM_DELTA mode")

        if hold is not None:
            pt_last = unpad(hold, bs, self.padding)
            fout.write(pt_last)

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
        blocks = list(split_blocks(padded, self.block_size))
        args = [(block, self.primitive_class, self.key) for block in blocks]
        results = list(self._executor.map(_encrypt_block_worker, args))
        return b''.join(results)

    def _decrypt_ecb(self, data: bytes) -> bytes:
        if len(data) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size for ECB")
        blocks = list(split_blocks(data, self.block_size))
        args = [(block, self.primitive_class, self.key) for block in blocks]
        results = list(self._executor.map(_decrypt_block_worker, args))
        joined = b"".join(results)
        return unpad(joined, self.block_size, self.padding)

    def _encrypt_cbc(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = list(split_blocks(padded, self.block_size))
        prev_cipher = iv
        ciphertext = []
        for P_i in blocks:
            x = xor_bytes(P_i, prev_cipher)
            C_i = self.primitive.encrypt_block(x)
            ciphertext.append(C_i)
            prev_cipher = C_i
        return iv + b''.join(ciphertext)

    def _decrypt_cbc(self, data: bytes) -> bytes:
        if len(data) < self.block_size:
            raise ValueError("Ciphertext too short for CBC mode")
        iv = data[:self.block_size]
        blocks = list(split_blocks(data[self.block_size:], self.block_size))
        prev_cipher = iv
        plaintext = []
        for C_i in blocks:
            x = self.primitive.decrypt_block(C_i)
            P_i = xor_bytes(x, prev_cipher)
            plaintext.append(P_i)
            prev_cipher = C_i
        return unpad(b''.join(plaintext), self.block_size, self.padding)

    def _encrypt_pcbc(self, data: bytes) -> bytes:
        padded = pad(data, self.block_size, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = list(split_blocks(padded, self.block_size))
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
        blocks = list(split_blocks(data[self.block_size:], self.block_size))
        prev_cipher = iv
        prev_plain = b'\x00' * self.block_size
        plaintext = []
        for C_i in blocks:
            x = self.primitive.decrypt_block(C_i)
            P_i = xor_bytes(x, xor_bytes(prev_plain, prev_cipher))
            plaintext.append(P_i)
            prev_plain, prev_cipher = P_i, C_i
        return unpad(b''.join(plaintext), self.block_size, self.padding)

    def _encrypt_cfb(self, data: bytes) -> bytes:
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        full_blocks_count = len(data) // self.block_size
        full_data = data[:full_blocks_count * self.block_size]
        tail = data[full_blocks_count * self.block_size:]
        prev_cipher = iv
        ciphertext = []
        for P_i in split_blocks(full_data, self.block_size):
            S_i = self.primitive.encrypt_block(prev_cipher)
            C_i = xor_bytes(P_i, S_i)
            ciphertext.append(C_i)
            prev_cipher = C_i
        if tail:
            S_i = self.primitive.encrypt_block(prev_cipher)
            C_tail = xor_bytes(tail, S_i[:len(tail)])
            ciphertext.append(C_tail)
        return iv + b''.join(ciphertext)

    def _decrypt_cfb(self, data: bytes) -> bytes:
        if len(data) < self.block_size:
            raise ValueError("Ciphertext too short for CFB mode")
        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]
        full_blocks_count = len(ciphertext) // self.block_size
        full_data = ciphertext[:full_blocks_count * self.block_size]
        tail = ciphertext[full_blocks_count * self.block_size:]
        prev_cipher = iv
        plaintext = []
        for C_i in split_blocks(full_data, self.block_size):
            S_i = self.primitive.encrypt_block(prev_cipher)
            P_i = xor_bytes(C_i, S_i)
            plaintext.append(P_i)
            prev_cipher = C_i
        if tail:
            S_i = self.primitive.encrypt_block(prev_cipher)
            P_tail = xor_bytes(tail, S_i[:len(tail)])
            plaintext.append(P_tail)
        return b''.join(plaintext)

    def _encrypt_ofb(self, data: bytes) -> bytes:
        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        full_blocks_count = len(data) // self.block_size
        full_data = data[:full_blocks_count * self.block_size]
        tail = data[full_blocks_count * self.block_size:]
        S_prev = iv
        ciphertext = []
        for P_i in split_blocks(full_data, self.block_size):
            S_i = self.primitive.encrypt_block(S_prev)
            C_i = xor_bytes(P_i, S_i)
            ciphertext.append(C_i)
            S_prev = S_i
        if tail:
            S_i = self.primitive.encrypt_block(S_prev)
            C_tail = xor_bytes(tail, S_i[:len(tail)])
            ciphertext.append(C_tail)
        return iv + b''.join(ciphertext)

    def _decrypt_ofb(self, data: bytes) -> bytes:
        if len(data) < self.block_size:
            raise ValueError("Ciphertext too short for OFB mode")
        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]
        full_blocks_count = len(ciphertext) // self.block_size
        full_data = ciphertext[:full_blocks_count * self.block_size]
        tail = ciphertext[full_blocks_count * self.block_size:]
        S_prev = iv
        plaintext = []
        for C_i in split_blocks(full_data, self.block_size):
            S_i = self.primitive.encrypt_block(S_prev)
            P_i = xor_bytes(C_i, S_i)
            plaintext.append(P_i)
            S_prev = S_i
        if tail:
            S_i = self.primitive.encrypt_block(S_prev)
            P_tail = xor_bytes(tail, S_i[:len(tail)])
            plaintext.append(P_tail)
        return b''.join(plaintext)

    def _encrypt_ctr(self, data: bytes) -> bytes:
        nonce = self.iv if self.iv else secrets.token_bytes(self.block_size // 2)
        full_blocks_count = len(data) // self.block_size
        full_data = data[:full_blocks_count * self.block_size]
        tail = data[full_blocks_count * self.block_size:]

        blocks = list(split_blocks(full_data, self.block_size))
        counters = list(range(len(blocks)))
        args = [(nonce, cnt, self.block_size, self.primitive_class, self.key) for cnt in counters]
        keystreams = list(self._executor.map(_ctr_encrypt_worker, args))
        ciphertext = [xor_bytes(block, ks) for block, ks in zip(blocks, keystreams)]

        if tail:
            counter_bytes = len(blocks).to_bytes(self.block_size // 2, "big")
            T_j = nonce + counter_bytes
            O_j = self.primitive.encrypt_block(T_j)
            C_tail = xor_bytes(tail, O_j[:len(tail)])
            ciphertext.append(C_tail)

        return nonce + b''.join(ciphertext)

    def _decrypt_ctr(self, data: bytes) -> bytes:
        if len(data) < self.block_size // 2:
            raise ValueError("Ciphertext too short for CTR mode")
        nonce = data[:self.block_size // 2]
        ciphertext = data[self.block_size // 2:]
        full_blocks_count = len(ciphertext) // self.block_size
        full_data = ciphertext[:full_blocks_count * self.block_size]
        tail = ciphertext[full_blocks_count * self.block_size:]

        blocks = list(split_blocks(full_data, self.block_size))
        counters = list(range(len(blocks)))
        args = [(nonce, cnt, self.block_size, self.primitive_class, self.key) for cnt in counters]
        keystreams = list(self._executor.map(_ctr_encrypt_worker, args))
        plaintext = [xor_bytes(block, ks) for block, ks in zip(blocks, keystreams)]

        if tail:
            counter_bytes = len(blocks).to_bytes(self.block_size // 2, "big")
            T_j = nonce + counter_bytes
            O_j = self.primitive.encrypt_block(T_j)
            P_tail = xor_bytes(tail, O_j[:len(tail)])
            plaintext.append(P_tail)

        return b''.join(plaintext)

    def _encrypt_random_delta(self, data: bytes) -> bytes:

        padded = pad(data, self.block_size, self.padding)

        iv = self.iv if self.iv else secrets.token_bytes(self.block_size)
        blocks = list(split_blocks(padded, self.block_size))
        prev_cipher = iv
        output_parts = [iv]
        for p_block in blocks:
            delta = secrets.token_bytes(self.block_size)
            x_in = xor_bytes(p_block, prev_cipher)
            x_out = self.primitive.encrypt_block(x_in)
            c_block = xor_bytes(x_out, delta)
            output_parts.append(delta)
            output_parts.append(c_block)
            prev_cipher = c_block
        return b''.join(output_parts)

    def _decrypt_random_delta(self, data: bytes) -> bytes:
        if len(data) < self.block_size:
            raise ValueError("Ciphertext too short for RANDOM_DELTA mode")
        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]
        if len(ciphertext) % (self.block_size * 2) != 0:
            raise ValueError("Invalid ciphertext length for RANDOM_DELTA mode")
        combined_blocks = list(split_blocks(ciphertext, self.block_size * 2))
        prev_cipher = iv
        plaintext_parts = []
        for combined in combined_blocks:
            delta = combined[:self.block_size]
            c_block = combined[self.block_size:]
            x_out = xor_bytes(c_block, delta)
            x_in = self.primitive.decrypt_block(x_out)
            p_block = xor_bytes(x_in, prev_cipher)
            plaintext_parts.append(p_block)
            prev_cipher = c_block
        padded_plaintext = b''.join(plaintext_parts)
        return unpad(padded_plaintext, self.block_size, self.padding)
