
import asyncio
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from crypto.utility.modes import PaddingMode, CipherMode
from crypto.cipher_modes.ecb_mode import ECBMode
from crypto.cipher_modes.cbc_mode import CBCMode
from crypto.cipher_modes.pcbc_mode import PCBCMode
from crypto.cipher_modes.cfb_mode import CFBMode
from crypto.cipher_modes.ofb_mode import OFBMode
from crypto.cipher_modes.ctr_mode import CTRMode
from crypto.cipher_modes.random_delta_mode import RandomDeltaMode


class SymmetricCipherContext:
    _MODE_CLASSES = {
        CipherMode.ECB: ECBMode,
        CipherMode.CBC: CBCMode,
        CipherMode.PCBC: PCBCMode,
        CipherMode.CFB: CFBMode,
        CipherMode.OFB: OFBMode,
        CipherMode.CTR: CTRMode,
        CipherMode.RANDOM_DELTA: RandomDeltaMode,
    }

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

        mode_class = self._MODE_CLASSES.get(mode)
        if not mode_class:
            raise NotImplementedError(f"Mode {mode} not implemented")

        self._mode_instance = mode_class(
            primitive=self.primitive,
            primitive_class=self.primitive_class,
            key=self.key,
            block_size=self.block_size,
            padding=self.padding,
            iv=self.iv,
            executor=self._executor,
            thread_local=self._thread_local,
        )

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
            kwargs = {}
            if hasattr(self.primitive, "key_size_bits"):
                kwargs["key_size"] = self.primitive.key_size_bits

            prim = self.primitive_class(**kwargs)
            prim.setup_keys(self.key)
            self._thread_local.primitive = prim
        return self._thread_local.primitive

    async def encrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._mode_instance.encrypt_bytes, data)

    async def decrypt_bytes(self, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._mode_instance.decrypt_bytes, data)

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
            self._mode_instance.encrypt_file(fin, fout, chunk_size)

    def _decrypt_file_sync(
        self, input_path: str, output_path: str, chunk_size: int
    ) -> None:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            self._mode_instance.decrypt_file(fin, fout, chunk_size)
