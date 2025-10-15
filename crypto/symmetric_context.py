import asyncio
import os
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from modes import PaddingMode, CipherMode
from utility import xor_bytes, split_blocks, pad, unpad


class SymmetricCipherContext:
    def __init__(
        self,
        primitive,
        key: bytes,
        mode: CipherMode = CipherMode.ECB,
        padding: PaddingMode = PaddingMode.PKCS7,
        iv: Optional[bytes] = None,
        max_workers: Optional[int] = None,
        *mode_args,
    ):

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

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers or (os.cpu_count() * 2)
        )
        self._thread_local = threading.local()
        self._validate_iv()

    def _validate_iv(self):
        if self.iv is None:
            return
        if self.mode in (
            CipherMode.CBC,
            CipherMode.PCBC,
            CipherMode.CFB,
            CipherMode.OFB,
        ):
            if len(self.iv) != self.block_size:
                raise ValueError(
                    f"IV must be {self.block_size} bytes for {self.mode.name} mode"
                )
        elif self.mode == CipherMode.CTR:
            if len(self.iv) != self.block_size // 2:
                raise ValueError(
                    f"IV (nonce) must be {self.block_size // 2} bytes for CTR mode"
                )
        elif self.mode == CipherMode.RANDOM_DELTA:
            if len(self.iv) != self.block_size:
                raise ValueError(
                    f"IV must be {self.block_size} bytes for RANDOM_DELTA mode"
                )

    def __del__(self):
        if hasattr(self, "_executor"):
            self._executor.shutdown(wait=True)

    def _get_thread_primitive(self):
        if not hasattr(self._thread_local, "primitive"):
            prim = self.primitive_class()
            prim.setup_keys(self.key)
            self._thread_local.primitive = prim
        return self._thread_local.primitive

    def _worker_encrypt(self, block):
        prim = self._get_thread_primitive()
        return prim.encrypt_block(block)

    def _worker_decrypt(self, block):
        prim = self._get_thread_primitive()
        return prim.decrypt_block(block)

    def _worker_ctr(self, args):
        nonce, counter = args
        prim = self._get_thread_primitive()
        counter_bytes = counter.to_bytes(self.block_size // 2, "big")
        return prim.encrypt_block(nonce + counter_bytes)

    async def encrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._encrypt_sync, data)

    async def decrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._decrypt_sync, data)

    async def encrypt_file(
        self, input_path: str, output_path: str, chunk_size: int = 1024 * 1024
    ) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._encrypt_file_sync, input_path, output_path, chunk_size
        )
        print(f"File encrypted successfully: {input_path} -> {output_path}")

    async def decrypt_file(
        self, input_path: str, output_path: str, chunk_size: int = 1024 * 1024
    ) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._decrypt_file_sync, input_path, output_path, chunk_size
        )
        print(f"File decrypted successfully: {input_path} -> {output_path}")

    def _encrypt_file_sync(
        self, input_path: str, output_path: str, chunk_size: int
    ) -> None:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            match self.mode:
                case CipherMode.ECB:
                    self._encrypt_ecb_file(fin, fout, chunk_size)
                case CipherMode.CBC:
                    self._encrypt_cbc_file(fin, fout, chunk_size)
                case CipherMode.PCBC:
                    self._encrypt_pcbc_file(fin, fout, chunk_size)
                case CipherMode.CFB:
                    self._process_cfb_file(fin, fout, chunk_size, True)
                case CipherMode.OFB:
                    self._process_ofb_file(fin, fout, chunk_size, True)
                case CipherMode.CTR:
                    self._process_ctr_file(fin, fout, chunk_size, True)
                case CipherMode.RANDOM_DELTA:
                    self._encrypt_random_delta_file(fin, fout, chunk_size)
                case _:
                    raise NotImplementedError(f"Mode {self.mode} not implemented")

    def _decrypt_file_sync(
        self, input_path: str, output_path: str, chunk_size: int
    ) -> None:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            match self.mode:
                case CipherMode.ECB:
                    self._decrypt_ecb_file(fin, fout, chunk_size)
                case CipherMode.CBC:
                    self._decrypt_cbc_file(fin, fout, chunk_size)
                case CipherMode.PCBC:
                    self._decrypt_pcbc_file(fin, fout, chunk_size)
                case CipherMode.CFB:
                    self._process_cfb_file(fin, fout, chunk_size, False)
                case CipherMode.OFB:
                    self._process_ofb_file(fin, fout, chunk_size, False)
                case CipherMode.CTR:
                    self._process_ctr_file(fin, fout, chunk_size, False)
                case CipherMode.RANDOM_DELTA:
                    self._decrypt_random_delta_file(fin, fout, chunk_size)
                case _:
                    raise NotImplementedError(f"Mode {self.mode} not implemented")

    def _encrypt_sync(self, data: bytes) -> bytes:
        match self.mode:
            case CipherMode.ECB:
                return self._encrypt_ecb(data)
            case CipherMode.CBC:
                return self._encrypt_cbc(data)
            case CipherMode.PCBC:
                return self._encrypt_pcbc(data)
            case CipherMode.CFB:
                return self._process_cfb(data, True)
            case CipherMode.OFB:
                return self._process_ofb(data, True)
            case CipherMode.CTR:
                return self._process_ctr(data, True)
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
                return self._process_cfb(data, False)
            case CipherMode.OFB:
                return self._process_ofb(data, False)
            case CipherMode.CTR:
                return self._process_ctr(data, False)
            case CipherMode.RANDOM_DELTA:
                return self._decrypt_random_delta(data)
            case _:
                raise NotImplementedError(f"Mode {self.mode} not implemented")

    def _encrypt_ecb_file(self, fin, fout, chunk_size):
        """Формула: C_i = E_K(P_i)"""
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

    def _decrypt_ecb_file(self, fin, fout, chunk_size):
        """Формула: P_i = D_K(C_i)"""
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

    def _encrypt_ecb(self, data: bytes) -> bytes:
        """Формула: C_i = E_K(P_i)"""
        bs = self.block_size
        padded = pad(data, bs, self.padding)
        blocks = list(split_blocks(padded, bs))
        results = list(self._executor.map(self._worker_encrypt, blocks))
        return b"".join(results)

    def _decrypt_ecb(self, data: bytes) -> bytes:
        """Формула: P_i = D_K(C_i)"""
        bs = self.block_size
        if len(data) % bs != 0:
            raise ValueError("Ciphertext length must be multiple of block size for ECB")
        blocks = list(split_blocks(data, bs))
        results = list(self._executor.map(self._worker_decrypt, blocks))
        return unpad(b"".join(results), bs, self.padding)

    def _encrypt_cbc_file(self, fin, fout, chunk_size):
        """Шифрование: C_i = E_K(P_i XOR C_{i-1}), C_0 = IV"""
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

    def _decrypt_cbc_file(self, fin, fout, chunk_size):
        """Дешифрование: P_i = D_K(C_i) XOR C_{i-1}"""
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

    def _encrypt_cbc(self, data: bytes) -> bytes:
        """Шифрование: C_i = E_K(P_i XOR C_{i-1}), C_0 = IV"""
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

    def _decrypt_cbc(self, data: bytes) -> bytes:
        """Дешифрование: P_i = D_K(C_i) XOR C_{i-1}"""
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

    def _encrypt_pcbc_file(self, fin, fout, chunk_size):
        """Шифрование: C_i = E_K(P_i XOR P_{i-1} XOR C_{i-1}), P_{0} = 0, C_0 = IV"""
        bs = self.block_size
        iv = self.iv if self.iv else secrets.token_bytes(bs)
        fout.write(iv)
        prev_c, prev_p = iv, b"\x00" * bs
        carry = b""

        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break

            data = carry + chunk
            full_len = (len(data) // bs) * bs
            full, carry = data[:full_len], data[full_len:]

            for p in split_blocks(full, bs):
                c = self.primitive.encrypt_block(
                    xor_bytes(p, xor_bytes(prev_p, prev_c))
                )
                fout.write(c)
                prev_p, prev_c = p, c

        for p in split_blocks(pad(carry, bs, self.padding), bs):
            c = self.primitive.encrypt_block(xor_bytes(p, xor_bytes(prev_p, prev_c)))
            fout.write(c)
            prev_p, prev_c = p, c

    def _decrypt_pcbc_file(self, fin, fout, chunk_size):
        """Дешифрование: P_i = D_K(C_i) XOR P_{i-1} XOR C_{i-1}"""
        bs = self.block_size
        iv = fin.read(bs)
        if len(iv) != bs:
            raise ValueError("Ciphertext too short for PCBC mode")

        prev_c, prev_p = iv, b"\x00" * bs
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
                    plaintext_block = xor_bytes(dec_block, xor_bytes(prev_p, prev_c))

                    if hold is not None:
                        fout.write(hold)
                    hold = plaintext_block
                    prev_p, prev_c = plaintext_block, blocks[i]

        if carry:
            raise ValueError("Ciphertext length invalid for PCBC mode")

        if hold is not None:
            fout.write(unpad(hold, bs, self.padding))

    def _encrypt_pcbc(self, data: bytes) -> bytes:
        """Шифрование: C_i = E_K(P_i XOR P_{i-1} XOR C_{i-1}), P_{-1} = 0, C_0 = IV"""
        bs = self.block_size
        padded = pad(data, bs, self.padding)
        iv = self.iv if self.iv else secrets.token_bytes(bs)

        prev_cipher = iv
        prev_plain = b"\x00" * bs
        ciphertext = [iv]

        for P_i in split_blocks(padded, bs):
            C_i = self.primitive.encrypt_block(
                xor_bytes(P_i, xor_bytes(prev_plain, prev_cipher))
            )
            ciphertext.append(C_i)
            prev_plain, prev_cipher = P_i, C_i

        return b"".join(ciphertext)

    def _decrypt_pcbc(self, data: bytes) -> bytes:
        """Дешифрование: P_i = D_K(C_i) XOR P_{i-1} XOR C_{i-1}"""
        bs = self.block_size
        if len(data) < bs or (len(data) - bs) % bs != 0:
            raise ValueError("Invalid ciphertext for PCBC")

        iv = data[:bs]
        ciphertext_blocks = list(split_blocks(data[bs:], bs))

        if not ciphertext_blocks:
            return b""

        decrypted_blocks = list(
            self._executor.map(self._worker_decrypt, ciphertext_blocks)
        )

        prev_cipher = iv
        prev_plain = b"\x00" * bs
        plaintext = []

        for i, dec_block in enumerate(decrypted_blocks):
            P_i = xor_bytes(dec_block, xor_bytes(prev_plain, prev_cipher))
            plaintext.append(P_i)
            prev_plain = P_i
            prev_cipher = ciphertext_blocks[i]

        return unpad(b"".join(plaintext), bs, self.padding)

    def _process_cfb_file(self, fin, fout, chunk_size, encrypt):
        """
        Шифрование: C_i = P_i XOR E_K(C_{i-1}), C_0 = IV
        Дешифрование: P_i = C_i XOR E_K(C_{i-1})
        """
        bs = self.block_size

        if encrypt:
            iv = self.iv if self.iv else secrets.token_bytes(bs)
            fout.write(iv)
            prev_cipher = iv
        else:
            iv = fin.read(bs)
            if len(iv) != bs:
                raise ValueError("Ciphertext too short for CFB mode")
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
                prev_cipher = output if encrypt else block

        if carry:
            s = self.primitive.encrypt_block(prev_cipher)
            fout.write(xor_bytes(carry, s[: len(carry)]))

    def _process_cfb(self, data: bytes, encrypt: bool) -> bytes:
        """
        Шифрование: C_i = P_i XOR E_K(C_{i-1}), C_0 = IV
        Дешифрование: P_i = C_i XOR E_K(C_{i-1})
        """
        bs = self.block_size

        iv = self.iv if self.iv else secrets.token_bytes(bs)
        if not encrypt:
            if len(data) < bs:
                raise ValueError("Ciphertext too short for CFB mode")
            iv = data[:bs]
            data = data[bs:]

        full_blocks_count = len(data) // bs
        full_data = data[: full_blocks_count * bs]
        tail = data[full_blocks_count * bs :]

        prev_cipher = iv
        output = []

        for block in split_blocks(full_data, bs):
            s = self.primitive.encrypt_block(prev_cipher)
            result = xor_bytes(block, s)
            output.append(result)
            prev_cipher = result if encrypt else block

        if tail:
            s = self.primitive.encrypt_block(prev_cipher)
            output.append(xor_bytes(tail, s[: len(tail)]))

        result_data = b"".join(output)
        return (iv + result_data) if encrypt else result_data

    def _process_ofb_file(self, fin, fout, chunk_size, encrypt):
        """
        Шифрование: S_i = E_K(S_{i-1}), C_i = P_i XOR S_i, S_0 = IV
        Дешифрование: S_i = E_K(S_{i-1}), P_i = C_i XOR S_i
        """
        bs = self.block_size

        if encrypt:
            iv = self.iv if self.iv else secrets.token_bytes(bs)
            fout.write(iv)
            prev_cipher = iv
        else:
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

    def _process_ofb(self, data: bytes, encrypt: bool) -> bytes:
        """
        Шифрование: S_i = E_K(S_{i-1}), C_i = P_i XOR S_i, S_0 = IV
        Дешифрование: P_i = C_i XOR S_i, где S_i = E_K(S_{i-1})
        """
        bs = self.block_size

        iv = self.iv if self.iv else secrets.token_bytes(bs)
        if not encrypt:
            if len(data) < bs:
                raise ValueError("Ciphertext too short for OFB mode")
            iv = data[:bs]
            data = data[bs:]

        full_blocks_count = len(data) // bs
        full_data = data[: full_blocks_count * bs]
        tail = data[full_blocks_count * bs :]

        prev_cipher = iv
        output = []

        for block in split_blocks(full_data, bs):
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            output.append(xor_bytes(block, prev_cipher))

        if tail:
            prev_cipher = self.primitive.encrypt_block(prev_cipher)
            output.append(xor_bytes(tail, prev_cipher[: len(tail)]))

        result_data = b"".join(output)
        return (iv + result_data) if encrypt else result_data

    def _process_ctr_file(self, fin, fout, chunk_size, encrypt):
        """
        Шифрование: T_j = Nonce || Counter_j, O_j = E_K(T_j), C_j = P_j XOR O_j
        Дешифрование: P_j = C_j XOR O_j
        """
        bs = self.block_size

        if encrypt:
            nonce = self.iv if self.iv else secrets.token_bytes(bs // 2)
            fout.write(nonce)
        else:
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

    def _process_ctr(self, data: bytes, encrypt: bool) -> bytes:
        """
        Шифрование: T_j = Nonce || Counter_j, O_j = E_K(T_j), C_j = P_j XOR O_j
        Дешифрование: P_j = C_j XOR O_j
        """
        bs = self.block_size

        nonce = self.iv if self.iv else secrets.token_bytes(bs // 2)
        if not encrypt:
            if len(data) < bs // 2:
                raise ValueError("Ciphertext too short for CTR mode")
            nonce = data[: bs // 2]
            data = data[bs // 2 :]

        full_blocks_count = len(data) // bs
        full_data = data[: full_blocks_count * bs]
        tail = data[full_blocks_count * bs :]

        blocks = list(split_blocks(full_data, bs))
        counters = [(nonce, i) for i in range(len(blocks))]
        keystreams = list(self._executor.map(self._worker_ctr, counters))
        output = [xor_bytes(block, ks) for block, ks in zip(blocks, keystreams)]

        if tail:
            counter_bytes = len(blocks).to_bytes(bs // 2, "big")
            O_j = self.primitive.encrypt_block(nonce + counter_bytes)
            output.append(xor_bytes(tail, O_j[: len(tail)]))

        result_data = b"".join(output)
        return (nonce + result_data) if encrypt else result_data

    def _encrypt_random_delta_file(self, fin, fout, chunk_size):
        """Шифрование: C_i = E_K(P_i XOR C_{i-1}) XOR Δ_i, C_0 = IV"""
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

    def _decrypt_random_delta_file(self, fin, fout, chunk_size):
        """Дешифрование: P_i = D_K(C_i XOR Δ_i) XOR C_{i-1}"""
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

    def _encrypt_random_delta(self, data: bytes) -> bytes:
        """Шифрование: C_i = E_K(P_i XOR C_{i-1}) XOR Δ_i, C_0 = IV"""
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

    def _decrypt_random_delta(self, data: bytes) -> bytes:
        """Дешифрование: P_i = D_K(C_i XOR Δ_i) XOR C_{i-1}"""
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
