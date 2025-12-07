import asyncio
import os
import secrets
import shutil
import time
import pytest

# Предполагаем, что RC4 реализует интерфейс, совместимый с вашим контекстом
# или тестируется напрямую как Stream Cipher.
from crypto.cipher_primitives.RC4.rc4_cipher import RC4
from crypto.utility.modes import CipherMode, PaddingMode
# Если RC4 не работает с контекстом, уберем этот импорт, но судя по запросу вы хотите "как в DES"
from crypto.utility.symmetric_context import SymmetricCipherContext


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_FILES_DIR = os.path.join(CURRENT_DIR, "test_files")
ENCRYPTED_DIR = os.path.join(TEST_FILES_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(TEST_FILES_DIR, "decrypted")


def reset_dir(path: str) -> None:
    """Очищает и пересоздает директорию."""
    try:
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print(f"Warning: could not reset {path}: {e}")


def hex_dump(data, max_len=32):
    """Красивый вывод байтов в HEX."""
    hex_str = data[:max_len].hex()
    formatted = " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))
    if len(data) > max_len:
        formatted += f" ... ({len(data)} bytes)"
    return formatted


@pytest.fixture(scope="function")
def clean_test_dirs():
    """Создает чистые директории для вывода перед тестом."""
    reset_dir(ENCRYPTED_DIR)
    reset_dir(DECRYPTED_DIR)
    yield


@pytest.fixture(scope="session")
def test_files_dir():
    """Гарантирует, что папка test_files существует."""
    os.makedirs(TEST_FILES_DIR, exist_ok=True)
    return TEST_FILES_DIR


@pytest.fixture(scope="module")
def user_files(test_files_dir):
    """
    Ищет файлы пользователя в папке test_files.
    Если папка пуста, создает пару тестовых файлов.
    """
    existing_files = [
        os.path.join(test_files_dir, f)
        for f in os.listdir(test_files_dir)
        if os.path.isfile(os.path.join(test_files_dir, f))
    ]

    if not existing_files:
        print(f"\n[setup] No files found in {test_files_dir}, generating defaults...")
        defaults = {
            "rc4_test_image.bin": secrets.token_bytes(1024 * 50), # 50 KB
            "rc4_test_text.txt": b"RC4 stream cipher verification file.\n" * 500,
        }
        generated = []
        for name, content in defaults.items():
            path = os.path.join(test_files_dir, name)
            with open(path, "wb") as f:
                f.write(content)
            generated.append(path)
        return generated
    else:
        print(f"\n[setup] Found {len(existing_files)} user files")
        return existing_files


def test_rc4_raw_primitive():
    """Тест 'сырого' RC4 (без контекста и режимов)."""
    print(f"\n--- [RC4] Raw Stream Test ---")

    key = b"Key"
    plaintext = b"Plaintext"
    expected = bytes.fromhex("bbf316e8d940af0ad3") # Wiki vector

    rc4 = RC4()
    rc4.setup_keys(key)

    print(f" Key:   {hex_dump(key)}")
    print(f" Input: {hex_dump(plaintext)}")

    # RC4 encrypt/decrypt is symmetric (XOR)
    ciphertext = rc4.encrypt(plaintext)
    print(f" Cipher:{hex_dump(ciphertext)}")

    assert ciphertext == expected, f"Vector mismatch! Got {ciphertext.hex()}"

    # Re-init for decrypt
    rc4_dec = RC4()
    rc4_dec.setup_keys(key)
    decrypted = rc4_dec.decrypt(ciphertext)

    print(f" Decr:  {hex_dump(decrypted)}")

    assert plaintext == decrypted
    assert len(ciphertext) == len(plaintext)


@pytest.mark.asyncio
async def test_rc4_memory_stream():
    """
    Проверяет работу RC4 как потокового шифра на данных разной длины.
    RC4 не использует Padding и Block Modes в классическом понимании,
    поэтому тестируем его "напрямую" или через контекст, если он поддерживает stream ciphers.
    """
    # Если SymmetricCipherContext поддерживает потоковые шифры (Stream Mode),
    # можно использовать его. Иначе тестируем напрямую класс RC4.

    # Предположим, мы тестируем напрямую класс RC4, так как режимы (CBC/ECB)
    # для него не имеют смысла (он сам генерирует поток).

    print(f"\n--- [RC4 | Stream Mode] ---")

    key = secrets.token_bytes(16)
    lengths = [1, 15, 128, 1024, 65535]

    for length in lengths:
        data = secrets.token_bytes(length)

        # Шифрование
        cipher_enc = RC4()
        cipher_enc.setup_keys(key)
        encrypted = cipher_enc.encrypt(data) # Обычный синхронный вызов

        # Дешифрование
        cipher_dec = RC4()
        cipher_dec.setup_keys(key)
        decrypted = cipher_dec.decrypt(encrypted)

        print(
            f" Len={length:<5} -> Enc={len(encrypted):<5} | In: {hex_dump(data, 10)} | Enc: {hex_dump(encrypted, 10)}"
        )

        if data != decrypted:
            print(f"\n!!! FAILURE !!!")
            pytest.fail(f"Decryption mismatch for len={length}")

    print(f" -> OK")


@pytest.mark.asyncio
async def test_rc4_file_encryption(clean_test_dirs, user_files):
    """
    Тест шифрования файлов для RC4.
    """
    # RC4 обычно не требует IV, но ключ обязателен.
    key = secrets.token_bytes(16)

    for f_path in user_files:
        f_name = os.path.basename(f_path)
        f_size = os.path.getsize(f_path)

        header = f"[RC4 | Stream | {f_name}]"
        print(f"\n--- {header} ---")

        enc_path = os.path.join(ENCRYPTED_DIR, f"RC4_{f_name}.enc")
        dec_path = os.path.join(DECRYPTED_DIR, f"RC4_{f_name}")

        try:
            # === Шифрование ===
            t0 = time.perf_counter()

            # Читаем и шифруем потоком (имитация, если нет async контекста)
            # В реальном приложении лучше использовать асинхронный контекст, если он есть.
            with open(f_path, "rb") as fin, open(enc_path, "wb") as fout:
                cipher = RC4()
                cipher.setup_keys(key)

                chunk_size = 64 * 1024 # 64KB
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    fout.write(cipher.encrypt(chunk)) # RC4 сохраняет состояние

            t_enc = time.perf_counter() - t0
            enc_size = os.path.getsize(enc_path)
            speed_enc = (f_size / 1024 / 1024) / t_enc if t_enc > 0 else 0
            print(f" Encrypt: {t_enc:.4f}s ({speed_enc:.2f} MB/s) -> {enc_size} bytes")

            # === Дешифрование ===
            t1 = time.perf_counter()

            with open(enc_path, "rb") as fin, open(dec_path, "wb") as fout:
                cipher = RC4()
                cipher.setup_keys(key) # Сброс состояния (новый ключ)

                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    fout.write(cipher.decrypt(chunk))

            t_dec = time.perf_counter() - t1
            speed_dec = (f_size / 1024 / 1024) / t_dec if t_dec > 0 else 0
            print(f" Decrypt: {t_dec:.4f}s ({speed_dec:.2f} MB/s)")

            # === Проверка ===
            if not os.path.exists(dec_path):
                raise FileNotFoundError("Decrypted file missing")

            if os.path.getsize(dec_path) != f_size:
                raise ValueError(
                    f"Size mismatch: {os.path.getsize(dec_path)} != {f_size}"
                )

            # Побайтовое сравнение
            with open(f_path, "rb") as f1, open(dec_path, "rb") as f2:
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
