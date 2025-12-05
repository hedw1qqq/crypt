import threading
from abc import ABC, abstractmethod
from typing import BinaryIO


class BaseCipherMode(ABC):

    def __init__(self, primitive, primitive_class, key, block_size, padding, iv, executor):
        self.primitive = primitive
        self.primitive_class = primitive_class
        self.key = key
        self.block_size = block_size
        self.padding = padding
        self.iv = iv
        self._executor = executor


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
