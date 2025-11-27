import pytest
import secrets
import os
import shutil
from crypto.cipher_primitives.rsa.rsa import RSA

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_FILES_DIR = os.path.join(CURRENT_DIR, "test_files")
ENCRYPTED_DIR = os.path.join(TEST_FILES_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(TEST_FILES_DIR, "decrypted")


def reset_dir(path: str):
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)


def encrypt_file_rsa(rsa_service, src_path: str, dst_path: str):

    key_size_bytes = (rsa_service.public_key.n.bit_length() + 7) // 8
    read_block_size = key_size_bytes - 1

    with open(src_path, "rb") as f_in, open(dst_path, "wb") as f_out:
        while chunk := f_in.read(read_block_size):
            m = int.from_bytes(chunk, byteorder="big")

            c = rsa_service.encrypt_int(m)

            encrypted_bytes = c.to_bytes(key_size_bytes, byteorder="big")

            f_out.write(len(chunk).to_bytes(4, byteorder="big"))
            f_out.write(encrypted_bytes)


def decrypt_file_rsa(rsa_service, src_path: str, dst_path: str):

    key_size_bytes = (rsa_service.private_key.n.bit_length() + 7) // 8

    with open(src_path, "rb") as f_in, open(dst_path, "wb") as f_out:
        while True:
            len_bytes = f_in.read(4)
            if not len_bytes:
                break
            original_len = int.from_bytes(len_bytes, byteorder="big")

            encrypted_chunk = f_in.read(key_size_bytes)
            if len(encrypted_chunk) != key_size_bytes:
                raise ValueError("broken chunk")

            c = int.from_bytes(encrypted_chunk, byteorder="big")

            m = rsa_service.decrypt_int(c)

            decrypted_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder="big")

            if len(decrypted_bytes) < original_len:
                decrypted_bytes = decrypted_bytes.rjust(original_len, b"\x00")

            f_out.write(decrypted_bytes)


@pytest.fixture(scope="module")
def rsa_service():
    print("\n[setup] generating rsa keys (1024 bits)...")
    return RSA(1024, 0.9999, RSA.PrimalityTest.MILLER_RABIN)


@pytest.fixture(scope="function")
def clean_test_dirs():
    reset_dir(ENCRYPTED_DIR)
    reset_dir(DECRYPTED_DIR)
    os.makedirs(TEST_FILES_DIR, exist_ok=True)
    yield


def test_encrypt_decrypt_int_cycle(rsa_service):
    print("\n[test] simple math cycle (int -> int)")

    m = 12345678901234567890987654321
    print(f"input: {m}")

    c = rsa_service.encrypt_int(m)
    print(f"enc: {c}")

    decrypted_m = rsa_service.decrypt_int(c)
    print(f"dec: {decrypted_m}")

    assert m == decrypted_m
    print("match ok")


def test_message_too_large_fails(rsa_service):
    print("\n[test] checking message > n limit")

    huge_m = 1 << 2000
    print(f"huge number bits: {huge_m.bit_length()}")

    try:
        rsa_service.encrypt_int(huge_m)
    except ValueError as e:
        print(f"caught expected error: {e}")
        return

    pytest.fail("should fail but didn't")


def test_file_encryption_list(rsa_service, clean_test_dirs):
    print("\n[test] file encryption loop")
    files = ["img_1.png", "test.txt"]

    for fname in files:
        path = os.path.join(TEST_FILES_DIR, fname)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(
                    secrets.token_bytes(2048) if "png" in fname else b"Hello RSA!" * 50
                )

    for fname in files:
        src = os.path.join(TEST_FILES_DIR, fname)
        enc = os.path.join(ENCRYPTED_DIR, fname + ".enc")
        dec = os.path.join(DECRYPTED_DIR, fname)

        print(f"\nfile: {fname}")
        encrypt_file_rsa(rsa_service, src, enc)

        size_enc = os.path.getsize(enc)
        print(f"encrypted size: {size_enc}")
        assert size_enc > 0

        decrypt_file_rsa(rsa_service, enc, dec)
        print(f"decrypted size: {os.path.getsize(dec)}")

        with open(src, "rb") as f1, open(dec, "rb") as f2:
            assert f1.read() == f2.read()
        print("checksum match")
