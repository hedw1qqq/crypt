import threading
from abc import ABC, abstractmethod
from typing import BinaryIO


class BaseCipherMode(ABC):

    def __init__(self, primitive, primitive_class, key, block_size, padding, iv, executor, thread_local):
        self.primitive = primitive
        self.primitive_class = primitive_class
        self.key = key
        self.block_size = block_size
        self.padding = padding
        self.iv = iv
        self._executor = executor
        self._thread_local = thread_local

    def _get_thread_primitive(self):
        if not hasattr(self._thread_local, "primitive"):
            kwargs = {}
            if hasattr(self.primitive, "key_size_bits"):
                kwargs["key_size"] = self.primitive.key_size_bits

            prim = self.primitive_class(**kwargs)
            prim.setup_keys(self.key)
            self._thread_local.primitive = prim
        return self._thread_local.primitive

    @abstractmethod
    def encrypt_bytes(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt_bytes(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def encrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        pass

    @abstractmethod
    def decrypt_file(self, fin: BinaryIO, fout: BinaryIO, chunk_size: int):
        pass
