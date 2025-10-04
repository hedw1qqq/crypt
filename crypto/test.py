from interfaces import ISymmetricCipher
from symmetric_context import SymmetricCipherContext
from modes import CipherMode
import secrets


class DummyBlockCipher(ISymmetricCipher):
    block_size = 8

    def __init__(self):
        self.round_keys: list[bytes] = []

    def setup_keys(self, key: bytes) -> None:
        self.round_keys = [key for _ in range(16)]

    def encrypt_block(self, block: bytes) -> bytes:
        processed_block = block
        for round_key in self.round_keys:
            processed_block = bytes(b ^ round_key[i % len(round_key)] for i, b in enumerate(processed_block))
        return processed_block

    def decrypt_block(self, block: bytes) -> bytes:
        processed_block = block
        for round_key in reversed(self.round_keys):
            processed_block = bytes(b ^ round_key[i % len(round_key)] for i, b in enumerate(processed_block))
        return processed_block


def test_ecb(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.ECB)  # Изменено
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "ECB: Расшифровка не совпадает с исходным текстом"
    blocks = [ciphertext[i:i + ctx.block_size] for i in range(0, len(ciphertext), ctx.block_size)]
    assert blocks[0] == blocks[2], "ECB: одинаковые блоки должны совпадать"
    print("ECB OK")


def test_cbc(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.CBC)  # Изменено
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "CBC: Расшифровка не совпадает с исходным текстом"
    blocks = [ciphertext[i:i + ctx.block_size] for i in range(ctx.block_size, len(ciphertext), ctx.block_size)]
    assert blocks[0] != blocks[2], "CBC: одинаковые блоки должны различаться"
    print("CBC OK")


def test_pcbc(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.PCBC)  # Изменено
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "PCBC: Расшифровка не совпадает с исходным текстом"
    print("PCBC OK")


def test_cfb(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.CFB)  # Изменено
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "CFB: Расшифровка не совпадает с исходным текстом"
    print("CFB OK")


def test_ofb(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.OFB)  # Изменено
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "OFB: Расшифровка не совпадает с исходным текстом"
    print("OFB OK")


def test_ctr(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.CTR)  # Изменено
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "CTR: Расшифровка не совпадает с исходным текстом"
    print("CTR OK")


def run_all_tests(context_class, primitive, key):
    test_ecb(context_class, primitive, key)
    test_cbc(context_class, primitive, key)
    test_pcbc(context_class, primitive, key)
    test_cfb(context_class, primitive, key)
    test_ofb(context_class, primitive, key)
    test_ctr(context_class, primitive, key)


run_all_tests(SymmetricCipherContext, DummyBlockCipher(), b"12345678")
