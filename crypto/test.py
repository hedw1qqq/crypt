from interfaces import ISymmetricCipher
from symmetric_context import SymmetricCipherContext
from modes import CipherMode
import secrets
import asyncio
import os
import tempfile


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


# ==================== ТЕСТЫ РЕЖИМОВ ШИФРОВАНИЯ ====================

def test_ecb(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.ECB)
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "ECB: Расшифровка не совпадает с исходным текстом"
    blocks = [ciphertext[i:i + ctx.block_size] for i in range(0, len(ciphertext), ctx.block_size)]
    assert blocks[0] == blocks[2], "ECB: одинаковые блоки должны совпадать"
    print("✓ ECB OK")


def test_cbc(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.CBC)
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "CBC: Расшифровка не совпадает с исходным текстом"
    blocks = [ciphertext[i:i + ctx.block_size] for i in range(ctx.block_size, len(ciphertext), ctx.block_size)]
    assert blocks[0] != blocks[2], "CBC: одинаковые блоки должны различаться"
    print("✓ CBC OK")


def test_pcbc(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.PCBC)
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "PCBC: Расшифровка не совпадает с исходным текстом"
    print("✓ PCBC OK")


def test_cfb(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.CFB)
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "CFB: Расшифровка не совпадает с исходным текстом"
    print("✓ CFB OK")


def test_ofb(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.OFB)
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "OFB: Расшифровка не совпадает с исходным текстом"
    print("✓ OFB OK")


def test_ctr(context_class, primitive, key):
    ctx = context_class(primitive, key, mode=CipherMode.CTR)
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)

    assert decrypted == data, "CTR: Расшифровка не совпадает с исходным текстом"
    print("✓ CTR OK")


def test_random_delta(context_class, primitive, key):
    """Тест режима Random Delta"""
    ctx = context_class(primitive, key, mode=CipherMode.RANDOM_DELTA)
    data = b"AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD"
    ciphertext = ctx._encrypt_sync(data)
    decrypted = ctx._decrypt_sync(ciphertext)
    assert decrypted == data, "RANDOM_DELTA: Расшифровка не совпадает с исходным текстом"
    bs = ctx.block_size
    if len(data) % bs == 0:
        padded_blocks = (len(data) // bs) + 1
    else:
        padded_blocks = (len(data) + bs - 1) // bs
    expected_len = bs + (padded_blocks * bs * 2)

    assert len(ciphertext) == expected_len, \
        f"RANDOM_DELTA: неверная длина шифротекста (ожидалось {expected_len}, получено {len(ciphertext)})"
    print("✓ RANDOM_DELTA OK")


# ==================== ТЕСТЫ НЕПОЛНЫХ БЛОКОВ (TAIL) ====================

def test_tail_handling():
    """Тест усечения гаммы для неполных блоков в потоковых режимах"""
    key = b"12345678"
    primitive = DummyBlockCipher()

    # Данные с неполным последним блоком (8+8+3 = 19 байт)
    data = b"AAAABBBBCCC"

    print("\n--- Тесты усечения гаммы (tail) ---")

    # CFB с неполным блоком
    ctx_cfb = SymmetricCipherContext(primitive, key, mode=CipherMode.CFB)
    ct_cfb = ctx_cfb._encrypt_sync(data)
    pt_cfb = ctx_cfb._decrypt_sync(ct_cfb)
    assert pt_cfb == data, "CFB: ошибка при обработке неполного блока"
    print("✓ CFB tail OK")

    # OFB с неполным блоком
    ctx_ofb = SymmetricCipherContext(primitive, key, mode=CipherMode.OFB)
    ct_ofb = ctx_ofb._encrypt_sync(data)
    pt_ofb = ctx_ofb._decrypt_sync(ct_ofb)
    assert pt_ofb == data, "OFB: ошибка при обработке неполного блока"
    print("✓ OFB tail OK")

    # CTR с неполным блоком
    ctx_ctr = SymmetricCipherContext(primitive, key, mode=CipherMode.CTR)
    ct_ctr = ctx_ctr._encrypt_sync(data)
    pt_ctr = ctx_ctr._decrypt_sync(ct_ctr)
    assert pt_ctr == data, "CTR: ошибка при обработке неполного блока"
    print("✓ CTR tail OK")

    # Проверка различных размеров хвоста
    for tail_size in [1, 3, 5, 7]:
        data_var = b"AAAABBBB" + b"X" * tail_size
        ctx = SymmetricCipherContext(primitive, key, mode=CipherMode.OFB)
        ct = ctx._encrypt_sync(data_var)
        pt = ctx._decrypt_sync(ct)
        assert pt == data_var, f"OFB: ошибка при tail_size={tail_size}"
    print(f"✓ Различные размеры tail (1-7 байт) OK")


# ==================== ТЕСТЫ ФАЙЛОВОГО ШИФРОВАНИЯ ====================

async def test_file_encryption():
    """Асинхронный тест шифрования файлов"""
    key = b"12345678"
    primitive = DummyBlockCipher()

    print("\n--- Тесты файлового шифрования ---")

    # Создаём временные файлы
    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, "input.txt")
        encrypted_file = os.path.join(tmpdir, "encrypted.bin")
        decrypted_file = os.path.join(tmpdir, "decrypted.txt")

        # Тестовые данные разных размеров
        test_cases = [
            (b"Short text", "короткий текст"),
            (b"A" * 100, "средний текст"),
            (b"B" * 1000, "длинный текст"),
            (b"C" * 8, "ровно 1 блок"),
            (b"D" * 19, "неполный последний блок"),
        ]

        modes_to_test = [
            CipherMode.ECB,
            CipherMode.CBC,
            CipherMode.PCBC,
            CipherMode.CFB,
            CipherMode.OFB,
            CipherMode.CTR,
        ]

        for mode in modes_to_test:
            for test_data, desc in test_cases:
                # Записываем исходные данные
                with open(input_file, "wb") as f:
                    f.write(test_data)

                # Создаём контекст
                ctx = SymmetricCipherContext(primitive, key, mode=mode)

                # Шифруем файл
                await ctx.encrypt_file(input_file, encrypted_file, chunk_size=16)

                # Дешифруем файл
                await ctx.decrypt_file(encrypted_file, decrypted_file, chunk_size=16)

                # Проверяем результат
                with open(decrypted_file, "rb") as f:
                    decrypted_data = f.read()

                assert decrypted_data == test_data, f"{mode.name}: файл ({desc}) не совпадает"

                # Очищаем файлы
                os.remove(encrypted_file)
                os.remove(decrypted_file)

            print(f"✓ {mode.name} файловое шифрование OK")


async def test_file_stream_modes():
    """Тест потокового шифрования больших файлов"""
    key = b"12345678"
    primitive = DummyBlockCipher()

    print("\n--- Тесты потокового шифрования ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, "large_input.bin")
        encrypted_file = os.path.join(tmpdir, "large_encrypted.bin")
        decrypted_file = os.path.join(tmpdir, "large_decrypted.bin")

        # Создаём большой файл (5 KB)
        large_data = secrets.token_bytes(5 * 1024)
        with open(input_file, "wb") as f:
            f.write(large_data)

        for mode in [CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR]:
            ctx = SymmetricCipherContext(primitive, key, mode=mode)

            # Шифруем с малым chunk_size для тестирования потоковой обработки
            await ctx.encrypt_file(input_file, encrypted_file, chunk_size=64)
            await ctx.decrypt_file(encrypted_file, decrypted_file, chunk_size=64)

            with open(decrypted_file, "rb") as f:
                decrypted_data = f.read()

            assert decrypted_data == large_data, f"{mode.name}: потоковая обработка не совпадает"

            os.remove(encrypted_file)
            os.remove(decrypted_file)

        print("✓ Потоковое шифрование больших файлов OK")


# ==================== ТЕСТЫ АСИНХРОННЫХ ОПЕРАЦИЙ ====================

async def test_async_bytes_encryption():
    """Тест асинхронного шифрования байтов"""
    key = b"12345678"
    primitive = DummyBlockCipher()

    print("\n--- Тесты асинхронного шифрования ---")

    data = b"Test async encryption and decryption"

    for mode in [CipherMode.ECB, CipherMode.CBC, CipherMode.OFB, CipherMode.CTR]:
        ctx = SymmetricCipherContext(primitive, key, mode=mode)

        # Асинхронное шифрование
        ciphertext = await ctx.encrypt_bytes(data)
        plaintext = await ctx.decrypt_bytes(ciphertext)

        assert plaintext == data, f"{mode.name}: асинхронная расшифровка не совпадает"

    print("✓ Асинхронное шифрование байтов OK")


# ==================== ЗАПУСК ВСЕХ ТЕСТОВ ====================

def run_all_tests(context_class, primitive, key):
    """Синхронные тесты режимов шифрования"""
    print("========== ТЕСТЫ РЕЖИМОВ ШИФРОВАНИЯ ==========")
    test_ecb(context_class, primitive, key)
    test_cbc(context_class, primitive, key)
    test_pcbc(context_class, primitive, key)
    test_cfb(context_class, primitive, key)
    test_ofb(context_class, primitive, key)
    test_ctr(context_class, primitive, key)
    test_random_delta(context_class, primitive, key)


async def run_async_tests():
    await test_file_encryption()
    await test_file_stream_modes()
    await test_async_bytes_encryption()


if __name__ == "__main__":
    run_all_tests(SymmetricCipherContext, DummyBlockCipher(), b"12345678")
    test_tail_handling()
    asyncio.run(run_async_tests())
    print("\n" + "=" * 50)
    print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
    print("=" * 50)
