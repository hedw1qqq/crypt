import asyncio
import os
import secrets
import shutil
import time

import pytest
from itertools import product

from crypto.cipher_primitives.rijndael.rijndael_cipher import RijndaelCipher
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
            "auto_test_text.txt": b"Rijndael encryption test file.\n" * 100,
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
    "key_len, expected_name",
    [
        (16, "AES-128"),
        (24, "AES-192"),
        (32, "AES-256"),
    ],
)
def test_aes_raw_primitive(key_len, expected_name):
    print(f"\n--- [{expected_name}] Raw Block Test ---")

    key = secrets.token_bytes(key_len)
    aes = RijndaelCipher(key_size=key_len, block_size=16)
    aes.setup_keys(key)

    plaintext = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
    print(f" Key:   {hex_dump(key)}")
    print(f" Input: {hex_dump(plaintext)}")

    ciphertext = aes.encrypt_block(plaintext)
    print(f" Cipher:{hex_dump(ciphertext)}")

    decrypted = aes.decrypt_block(ciphertext)
    print(f" Decr:  {hex_dump(decrypted)}")

    assert plaintext == decrypted
    assert len(ciphertext) == 16
    assert plaintext != ciphertext


@pytest.mark.asyncio
@pytest.mark.parametrize("key_len", [16, 24, 32])
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
async def test_aes_memory_full_matrix(key_len, mode, padding):
    aes_name = f"AES-{key_len*8}"
    header = f"[{aes_name} | {mode.name} | {padding.name}]"
    print(f"\n--- {header} ---")

    key = secrets.token_bytes(key_len)

    lengths = [16, 31, 100]

    for length in lengths:
        data = secrets.token_bytes(length)

        iv = None
        if mode == CipherMode.CTR:
            iv = secrets.token_bytes(8)
        elif mode != CipherMode.ECB:
            iv = secrets.token_bytes(16)

        aes = RijndaelCipher(key_size=key_len, block_size=16)
        ctx = SymmetricCipherContext(
            primitive=aes, key=key, mode=mode, padding=padding, iv=iv
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
            print(f" Decrypt:  {hex_dump(decrypted)}")
            pytest.fail(f"Decryption mismatch in {header}")

    print(f" -> OK")


@pytest.mark.asyncio
@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("mode", [CipherMode.CBC, CipherMode.CTR])
async def test_user_files_encryption_parametrized(clean_test_dirs, key_len, mode, user_files):
    aes_name = f"AES-{key_len*8}"
    key = secrets.token_bytes(key_len)

    for f_path in user_files:
        f_name = os.path.basename(f_path)
        f_size = os.path.getsize(f_path)

        header = f"[{aes_name} | {mode.name} | {f_name}]"
        print(f"\n--- {header} ---")

        iv = (
            secrets.token_bytes(8)
            if mode == CipherMode.CTR
            else secrets.token_bytes(16)
        )

        aes = RijndaelCipher(key_size=len(key), block_size=16)
        ctx = SymmetricCipherContext(
            primitive=aes, key=key, mode=mode, padding=PaddingMode.PKCS7, iv=iv
        )

        enc_path = os.path.join(ENCRYPTED_DIR, f"{aes_name}_{mode.name}_{f_name}.enc")
        dec_path = os.path.join(DECRYPTED_DIR, f"{aes_name}_{mode.name}_{f_name}")

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
