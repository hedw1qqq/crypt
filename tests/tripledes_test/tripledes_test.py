import asyncio
import os
import secrets
import shutil
import time
import pytest

from crypto.cipher_primitives.DES.triple_des import TripleDES
from crypto.utility.modes import CipherMode, PaddingMode
from crypto.utility.symmetric_context import SymmetricCipherContext

# --- Константы ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_FILES_DIR = os.path.join(CURRENT_DIR, "test_files")
ENCRYPTED_DIR = os.path.join(TEST_FILES_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(TEST_FILES_DIR, "decrypted")

# --- Утилиты ---

def reset_dir(path: str) -> None:
    """Очищает и создает папку."""
    try:
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print(f"Warning: {path}: {e}")

def hex_dump(data, max_len=32):
    """Вывод байтов в hex."""
    hex_str = data[:max_len].hex()
    formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    if len(data) > max_len:
        formatted += f" ... ({len(data)} bytes)"
    return formatted

# --- Фикстуры ---

@pytest.fixture(scope="function")
def clean_test_dirs():
    """Чистые папки для шифрованных файлов."""
    reset_dir(ENCRYPTED_DIR)
    reset_dir(DECRYPTED_DIR)
    yield

@pytest.fixture(scope="session")
def test_files_dir():
    """Гарантирует наличие test_files."""
    os.makedirs(TEST_FILES_DIR, exist_ok=True)
    return TEST_FILES_DIR

@pytest.fixture(scope="module")
def user_files(test_files_dir):
    """
    Ищет файлы пользователя в test_files.
    Если нет — создает дефолтные.
    """
    existing = [
        os.path.join(test_files_dir, f)
        for f in os.listdir(test_files_dir)
        if os.path.isfile(os.path.join(test_files_dir, f))
    ]

    if not existing:
        print(f"\n[setup] Создаю тестовые файлы в {test_files_dir}...")
        defaults = {
            "3des_test_image.bin": secrets.token_bytes(1024 * 5),
            "3des_test_text.txt": b"Triple DES test file.\n" * 100,
        }
        generated = []
        for name, content in defaults.items():
            path = os.path.join(test_files_dir, name)
            with open(path, "wb") as f:
                f.write(content)
            generated.append(path)
        return generated
    else:
        print(f"\n[setup] Найдено файлов: {len(existing)}")
        return existing

# --- Тесты ---

@pytest.mark.parametrize("tdes_mode,key_bytes", [
    ("EDE", b"\x01" * 8 + b"\x02" * 8),         # 16 байт (K3=K1)
    ("EEE", b"\x0A" * 8 + b"\x0B" * 8),         # 16 байт (K3=K1)
    ("EDE", b"\x11" * 8 + b"\x22" * 8 + b"\x33" * 8),  # 24 байта (все разные)
    ("EEE", b"\xAA" * 8 + b"\xBB" * 8 + b"\xCC" * 8),  # 24 байта (все разные)
])
def test_3des_raw_primitive(tdes_mode, key_bytes):
    """Проверка базового шифрования 3DES (один блок 8 байт)."""
    print(f"\n--- [3DES-{tdes_mode} | key={len(key_bytes)}B] Raw Block Test ---")

    tdes = TripleDES(mode=tdes_mode)
    tdes.setup_keys(key_bytes)

    plaintext = b"ABCDEFGH"  # 8 байт
    print(f" Key:   {hex_dump(key_bytes)}")
    print(f" Input: {hex_dump(plaintext)}")

    ciphertext = tdes.encrypt_block(plaintext)
    print(f" Cipher:{hex_dump(ciphertext)}")

    decrypted = tdes.decrypt_block(ciphertext)
    print(f" Decr:  {hex_dump(decrypted)}")

    assert plaintext == decrypted
    assert len(ciphertext) == 8
    assert plaintext != ciphertext


@pytest.mark.asyncio
@pytest.mark.parametrize("tdes_mode,key_len", [
    ("EDE", 16),
    ("EEE", 16),
    ("EDE", 24),
    ("EEE", 24),
])
@pytest.mark.parametrize("mode", [
    CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC,
    CipherMode.CFB, CipherMode.OFB, CipherMode.CTR,
    CipherMode.RANDOM_DELTA
])
@pytest.mark.parametrize("padding", [
    PaddingMode.PKCS7, PaddingMode.ISO_10126, PaddingMode.ANSI_X923
])
async def test_3des_memory_full_matrix(tdes_mode, key_len, mode, padding):
    """
    Проверяет ВСЕ комбинации: (3DES-EDE/EEE) x (16/24 byte key) x (Mode) x (Padding).
    """
    header = f"[3DES-{tdes_mode} | key={key_len}B | {mode.name} | {padding.name}]"
    print(f"\n--- {header} ---")

    # Генерация ключа нужной длины
    key = secrets.token_bytes(key_len)

    # Разные размеры данных (блок 3DES = 8 байт)
    lengths = [8, 17, 32]

    for length in lengths:
        data = secrets.token_bytes(length)

        # IV для режимов
        iv = None
        if mode == CipherMode.CTR:
            iv = secrets.token_bytes(4)  # Nonce 4 байта (половина от 8)
        elif mode != CipherMode.ECB:
            iv = secrets.token_bytes(8)  # Полный блок

        tdes = TripleDES(mode=tdes_mode)
        ctx = SymmetricCipherContext(
            primitive=tdes, key=key, mode=mode, padding=padding, iv=iv, max_workers=1
        )

        try:
            encrypted = await ctx.encrypt_bytes(data)
            decrypted = await ctx.decrypt_bytes(encrypted)
        except Exception as e:
            pytest.fail(f"{header} CRASH on len={length}: {e}")

        # Вывод
        print(f" Len={length:<3} -> Enc={len(encrypted):<3} | In: {hex_dump(data, 10)} | Enc: {hex_dump(encrypted, 10)}")

        if data != decrypted:
            print(f"\n!!! FAILURE !!!")
            print(f" Original: {hex_dump(data)}")
            print(f" Decrypt:  {hex_dump(decrypted)}")
            pytest.fail(f"Decryption mismatch in {header}")

    print(f" -> OK")


@pytest.mark.asyncio
@pytest.mark.parametrize("tdes_mode,key_len", [
    ("EDE", 16),
    ("EEE", 24),
])
@pytest.mark.parametrize("mode", [CipherMode.CBC, CipherMode.CTR])
async def test_3des_file_encryption_parametrized(clean_test_dirs, tdes_mode, key_len, mode, user_files):
    """
    Параметризованный тест файлов для 3DES.
    """
    key = secrets.token_bytes(key_len)

    for f_path in user_files:
        f_name = os.path.basename(f_path)
        f_size = os.path.getsize(f_path)

        header = f"[3DES-{tdes_mode} {key_len}B | {mode.name} | {f_name}]"
        print(f"\n--- {header} ---")

        # IV setup
        iv = secrets.token_bytes(4) if mode == CipherMode.CTR else secrets.token_bytes(8)

        tdes = TripleDES(mode=tdes_mode)
        ctx = SymmetricCipherContext(
            primitive=tdes, key=key, mode=mode, padding=PaddingMode.PKCS7, iv=iv, max_workers=1
        )

        enc_path = os.path.join(ENCRYPTED_DIR, f"3DES_{tdes_mode}_{mode.name}_{f_name}.enc")
        dec_path = os.path.join(DECRYPTED_DIR, f"3DES_{tdes_mode}_{mode.name}_{f_name}")

        try:
            # Шифрование
            t0 = time.perf_counter()
            await ctx.encrypt_file(f_path, enc_path)
            t_enc = time.perf_counter() - t0

            enc_size = os.path.getsize(enc_path)
            speed_enc = (f_size / 1024 / 1024) / t_enc if t_enc > 0 else 0

            print(f" Encrypt: {t_enc:.4f}s ({speed_enc:.2f} MB/s) -> {enc_size} bytes")

            # Дешифрование
            t1 = time.perf_counter()
            await ctx.decrypt_file(enc_path, dec_path)
            t_dec = time.perf_counter() - t1

            speed_dec = (f_size / 1024 / 1024) / t_dec if t_dec > 0 else 0
            print(f" Decrypt: {t_dec:.4f}s ({speed_dec:.2f} MB/s)")

            # Проверка
            if not os.path.exists(dec_path):
                raise FileNotFoundError("Decrypted file missing")

            if os.path.getsize(dec_path) != f_size:
                raise ValueError(f"Size mismatch: {os.path.getsize(dec_path)} != {f_size}")

            with open(f_path, "rb") as f1, open(dec_path, "rb") as f2:
                chunk_size = 65536
                while True:
                    b1 = f1.read(chunk_size)
                    b2 = f2.read(chunk_size)
                    if b1 != b2:
                        raise ValueError("Content mismatch")
                    if not b1:
                        break
            print(" -> OK (Checksum match)")

        except Exception as e:
            print(f"FAIL: {e}")
            pytest.fail(f"File test failed: {header} -> {e}")
