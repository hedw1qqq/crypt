import asyncio
import os
import secrets
import shutil
import time
import pytest
from crypto.cipher_primitives.rc5.rc5_cipher import RC5
from crypto.utility.modes import CipherMode, PaddingMode
from crypto.utility.symmetric_context import SymmetricCipherContext

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_FILES_DIR = os.path.join(CURRENT_DIR, "test_files")
ENCRYPTED_DIR = os.path.join(TEST_FILES_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(TEST_FILES_DIR, "decrypted")


def reset_dir(path: str) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print(f"Warning: could not reset {path}: {e}")


def hex_dump(data, max_len=32):
    hex_str = data[:max_len].hex()
    formatted = " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))
    if len(data) > max_len:
        formatted += f" ... ({len(data)} bytes)"
    return formatted


@pytest.fixture(scope="function")
def clean_test_dirs():
    reset_dir(ENCRYPTED_DIR)
    reset_dir(DECRYPTED_DIR)
    yield


@pytest.fixture(scope="session")
def test_files_dir():
    os.makedirs(TEST_FILES_DIR, exist_ok=True)
    return TEST_FILES_DIR


@pytest.fixture(scope="module")
def user_files(test_files_dir):
    existing_files = [
        os.path.join(test_files_dir, f)
        for f in os.listdir(test_files_dir)
        if os.path.isfile(os.path.join(test_files_dir, f))
    ]

    if not existing_files:
        print(f"\n[setup] No files found in {test_files_dir}, generating defaults...")
        defaults = {
            "auto_test_image.bin": secrets.token_bytes(1024 * 5),
            "auto_test_text.txt": b"RC5 encryption test file.\n" * 100,
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


@pytest.mark.parametrize(
    "word_size, num_rounds, expected_name",
    [
        (32, 12, "RC5-32/12"),
        (32, 16, "RC5-32/16"),
        (64, 12, "RC5-64/12"),
    ],
)
def test_rc5_raw_primitive(word_size, num_rounds, expected_name):
    print(f"\n--- [{expected_name}] Raw Block Test ---")
    key = secrets.token_bytes(16)
    rc5 = RC5(word_size=word_size, num_rounds=num_rounds)
    rc5.setup_keys(key)

    block_size = rc5.block_size
    plaintext = secrets.token_bytes(block_size)

    print(f" Key: {hex_dump(key)}")
    print(f" Input: {hex_dump(plaintext)}")

    ciphertext = rc5.encrypt_block(plaintext)
    print(f" Cipher:{hex_dump(ciphertext)}")

    decrypted = rc5.decrypt_block(ciphertext)
    print(f" Decr: {hex_dump(decrypted)}")

    assert plaintext == decrypted
    assert len(ciphertext) == block_size
    assert plaintext != ciphertext


@pytest.mark.parametrize(
    "word_size, num_rounds",
    [
        (16, 12),
        (32, 12),
        (64, 12),
    ],
)
def test_rc5_key_schedule(word_size, num_rounds):
    """Тест генерации ключей различной длины"""
    print(f"\n--- [RC5-{word_size}/{num_rounds}] Key Schedule Test ---")

    rc5 = RC5(word_size=word_size, num_rounds=num_rounds)

    for key_len in [8, 16, 24, 32]:
        key = secrets.token_bytes(key_len)
        print(f" Key length: {key_len} bytes -> {hex_dump(key, 16)}")

        try:
            rc5.setup_keys(key)
            expected_s_len = 2 * (num_rounds + 1)
            assert len(rc5.S) == expected_s_len
            print(f"   -> OK (Generated {len(rc5.S)} subkeys)")
        except Exception as e:
            pytest.fail(f"Key schedule failed for key_len={key_len}: {e}")


@pytest.mark.asyncio
@pytest.mark.parametrize("word_size", [32, 64])
@pytest.mark.parametrize("num_rounds", [12, 16])
@pytest.mark.parametrize(
    "mode",
    [
        CipherMode.ECB,
        CipherMode.CBC,
        CipherMode.PCBC,
        CipherMode.CFB,
        CipherMode.OFB,
        CipherMode.CTR,
        CipherMode.RANDOM_DELTA,
    ],
)
@pytest.mark.parametrize(
    "padding", [PaddingMode.PKCS7, PaddingMode.ISO_10126, PaddingMode.ANSI_X923]
)
async def test_rc5_memory_full_matrix(word_size, num_rounds, mode, padding):
    rc5_name = f"RC5-{word_size}/{num_rounds}"
    header = f"[{rc5_name} | {mode.name} | {padding.name}]"
    print(f"\n--- {header} ---")

    key = secrets.token_bytes(16)
    rc5 = RC5(word_size=word_size, num_rounds=num_rounds)
    block_size = rc5.block_size

    lengths = [block_size, block_size * 2 - 1, 100]

    for length in lengths:
        data = secrets.token_bytes(length)

        iv = None
        if mode == CipherMode.CTR:
            iv = secrets.token_bytes(block_size // 2)
        elif mode != CipherMode.ECB:
            iv = secrets.token_bytes(block_size)

        ctx = SymmetricCipherContext(
            primitive=rc5, key=key, mode=mode, padding=padding, iv=iv
        )

        try:
            encrypted = await ctx.encrypt_bytes(data)
            decrypted = await ctx.decrypt_bytes(encrypted)
        except Exception as e:
            pytest.fail(f"{header} CRASH on len={length}: {e}")

        print(
            f" Len={length:<3} -> Enc={len(encrypted):<3} | In: {hex_dump(data, 10)} | Enc: {hex_dump(encrypted, 10)}"
        )

        if data != decrypted:
            print(f"\n!!! FAILURE !!!")
            print(f" Original: {hex_dump(data)}")
            print(f" Decrypt: {hex_dump(decrypted)}")
            pytest.fail(f"Decryption mismatch in {header}")

        print(f" -> OK")


@pytest.mark.asyncio
@pytest.mark.parametrize("word_size", [32, 64])
@pytest.mark.parametrize("num_rounds", [12, 16, 254])
@pytest.mark.parametrize(
    "mode",
    [
        CipherMode.ECB,
        CipherMode.CBC,
        CipherMode.PCBC,
        CipherMode.CFB,
        CipherMode.OFB,
        CipherMode.CTR,
        CipherMode.RANDOM_DELTA,
    ],
)
async def test_user_files_encryption_parametrized(
    clean_test_dirs, word_size, mode, user_files, num_rounds
):
    rc5_name = f"RC5-{word_size}"
    key = secrets.token_bytes(16)

    for f_path in user_files:
        f_name = os.path.basename(f_path)
        f_size = os.path.getsize(f_path)
        header = f"[{rc5_name} | {mode.name} | {f_name}]"
        print(f"\n--- {header} ---")

        rc5 = RC5(word_size=word_size, num_rounds=num_rounds)
        block_size = rc5.block_size

        iv = (
            secrets.token_bytes(block_size // 2)
            if mode == CipherMode.CTR
            else secrets.token_bytes(block_size)
        )

        ctx = SymmetricCipherContext(
            primitive=rc5, key=key, mode=mode, padding=PaddingMode.PKCS7, iv=iv
        )

        enc_path = os.path.join(ENCRYPTED_DIR, f"{rc5_name}_{mode.name}_{f_name}.enc")
        dec_path = os.path.join(DECRYPTED_DIR, f"{rc5_name}_{mode.name}_{f_name}")

        try:
            t0 = time.perf_counter()
            await ctx.encrypt_file(f_path, enc_path)
            t_enc = time.perf_counter() - t0

            enc_size = os.path.getsize(enc_path)
            speed_enc = (f_size / 1024 / 1024) / t_enc if t_enc > 0 else 0
            print(f" Encrypt: {t_enc:.4f}s ({speed_enc:.2f} MB/s) -> {enc_size} bytes")

            t1 = time.perf_counter()
            await ctx.decrypt_file(enc_path, dec_path)
            t_dec = time.perf_counter() - t1

            speed_dec = (f_size / 1024 / 1024) / t_dec if t_dec > 0 else 0
            print(f" Decrypt: {t_dec:.4f}s ({speed_dec:.2f} MB/s)")

            if not os.path.exists(dec_path):
                raise FileNotFoundError("Decrypted file missing")

            if os.path.getsize(dec_path) != f_size:
                raise ValueError(
                    f"Size mismatch: {os.path.getsize(dec_path)} != {f_size}"
                )

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


@pytest.mark.parametrize("word_size", [32, 64])
def test_rc5_block_size(word_size):
    """Проверка корректности размера блока"""
    print(f"\n--- [RC5-{word_size}] Block Size Test ---")
    rc5 = RC5(word_size=word_size, num_rounds=12)
    expected_block_size = 2 * (word_size // 8)

    print(f" Expected block size: {expected_block_size} bytes")
    print(f" Actual block size: {rc5.block_size} bytes")

    assert rc5.block_size == expected_block_size


def test_rc5_invalid_word_size():
    """Проверка валидации размера слова"""
    print(f"\n--- [RC5] Invalid Word Size Test ---")

    invalid_sizes = [8, 24, 48, 128]
    for size in invalid_sizes:
        print(f" Testing invalid word_size={size}")
        with pytest.raises(ValueError):
            RC5(word_size=size, num_rounds=12)
        print(f"   -> Correctly rejected")
