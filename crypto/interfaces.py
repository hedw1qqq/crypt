from abc import ABC, abstractmethod


class IKeySchedule(ABC):
    @abstractmethod
    def expand_key(self, master_key: bytes) -> list[bytes]:
        pass


class IRoundFunction(ABC):
    @abstractmethod
    def apply(self, half_block: bytes, round_key: bytes) -> bytes:
        pass


class ISymmetricCipher(ABC):
    @abstractmethod
    def encrypt_block(self, block: bytes, round_key: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt_block(self, block: bytes, round_key: bytes) -> bytes:
        pass

    @abstractmethod
    def setup_keys(self, key: bytes) -> None:
        pass
