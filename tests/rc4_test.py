# crypto/tests/test_rc4.py

import os
import secrets
import shutil
import time
import unittest
from pathlib import Path

from crypto.cipher_primitives.RC4.rc4_cipher import RC4


def reset_dir(path: str) -> None:
    """Безопасная очистка и создание директории."""
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)


def format_bytes_hex(data, bytes_per_line=16):
    """Форматирование байт в hex с переносами строк."""
    hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        chunk = hex_str[i : i + bytes_per_line * 2]
        formatted = " ".join(chunk[j : j + 2] for j in range(0, len(chunk), 2))
        lines.append(f"    {formatted}")
    return "\n".join(lines)


class TestRC4(unittest.TestCase):

    def test_rc4_basic_roundtrip(self):
        """Базовый тест: шифрование и расшифрование."""
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ АЛГОРИТМА RC4 - БАЗОВЫЙ ROUNDTRIP")
        print("=" * 80)

        test_cases = [
            (b"Key", b"Plaintext"),
            (b"Wiki", b"pedia"),
            (b"Secret", b"Attack at dawn"),
            (b"\x01\x02\x03\x04\x05", b"RC4 Stream Cipher Test"),
            (secrets.token_bytes(16), secrets.token_bytes(64)),
        ]

        for key, plaintext in test_cases:
            print(f"\n{'─' * 80}")
            print(
                f"Ключ ({len(key)} байт): {key[:20].hex()}{'...' if len(key) > 20 else ''}"
            )
            print(
                f"Открытый текст ({len(plaintext)} байт): {plaintext[:40]!r}{'...' if len(plaintext) > 40 else ''}"
            )

            rc4_enc = RC4()
            rc4_enc.setup_keys(key)
            ciphertext = rc4_enc.encrypt(plaintext)

            print(
                f"Зашифрованный: {ciphertext[:40].hex()}{'...' if len(ciphertext) > 40 else ''}"
            )

            # Расшифрование с тем же ключом
            rc4_dec = RC4()
            rc4_dec.setup_keys(key)
            decrypted = rc4_dec.decrypt(ciphertext)

            match = plaintext == decrypted
            status = "✓ SUCCESS" if match else "✗ FAILED"
            print(f"Результат: {status}")

            self.assertEqual(
                plaintext, decrypted, "Расшифровка не совпала с оригиналом"
            )

    def test_rc4_different_key_lengths(self):
        """Тест с различными длинами ключей (5-256 байт)."""
        print("\n" + "=" * 80)
        print("RC4 С РАЗЛИЧНЫМИ ДЛИНАМИ КЛЮЧЕЙ")
        print("=" * 80)

        key_lengths = [5, 8, 16, 32, 64, 128, 256]
        plaintext = b"The quick brown fox jumps over the lazy dog"

        for key_len in key_lengths:
            key = secrets.token_bytes(key_len)

            rc4_enc = RC4()
            rc4_enc.setup_keys(key)
            ciphertext = rc4_enc.encrypt(plaintext)

            rc4_dec = RC4()
            rc4_dec.setup_keys(key)
            decrypted = rc4_dec.decrypt(ciphertext)

            match = plaintext == decrypted
            status = "✓" if match else "✗"

            print(
                f"  Ключ {key_len:3d} байт: {status} | CT длина: {len(ciphertext)} байт"
            )

            self.assertEqual(
                plaintext, decrypted, f"Не совпало для длины ключа {key_len}"
            )

    def test_rc4_various_data_sizes(self):
        """Тест с различными размерами данных."""
        print("\n" + "=" * 80)
        print("RC4 С РАЗЛИЧНЫМИ РАЗМЕРАМИ ДАННЫХ")
        print("=" * 80)

        key = b"TestKey123"
        data_sizes = [1, 10, 100, 1000, 10000, 100000]

        for size in data_sizes:
            plaintext = secrets.token_bytes(size)

            rc4_enc = RC4()
            rc4_enc.setup_keys(key)
            ciphertext = rc4_enc.encrypt(plaintext)

            rc4_dec = RC4()
            rc4_dec.setup_keys(key)
            decrypted = rc4_dec.decrypt(ciphertext)

            match = plaintext == decrypted
            status = "✓" if match else "✗"

            print(f"  Размер {size:6d} байт: {status}")

            self.assertEqual(plaintext, decrypted, f"Не совпало для размера {size}")

    def test_rc4_known_vectors(self):
        """Тест с известными тестовыми векторами RC4."""
        print("\n" + "=" * 80)
        print("RC4 ИЗВЕСТНЫЕ ТЕСТОВЫЕ ВЕКТОРЫ")
        print("=" * 80)

        # Тестовые векторы из RFC и других источников
        vectors = [
            (b"Key", b"Plaintext", bytes.fromhex("bbf316e8d940af0ad3")),
            (b"Wiki", b"pedia", bytes.fromhex("1021bf0420")),
            (
                b"Secret",
                b"Attack at dawn",
                bytes.fromhex("45a01f645fc35b383552544b9bf5"),
            ),
        ]

        for key, plaintext, expected_ct in vectors:
            rc4 = RC4()
            rc4.setup_keys(key)
            ciphertext = rc4.encrypt(plaintext)

            match = ciphertext == expected_ct
            status = "✓ PASS" if match else "✗ FAIL"

            print(f"\n  Key: {key!r}")
            print(f"  PT:  {plaintext!r}")
            print(f"  CT (expected): {expected_ct.hex()}")
            print(f"  CT (got):      {ciphertext.hex()}")
            print(f"  Status: {status}")

            self.assertEqual(
                ciphertext, expected_ct, f"Не совпал вектор для ключа {key!r}"
            )

    def test_rc4_empty_data(self):
        """Тест с пустыми данными."""
        print("\n" + "=" * 80)
        print("RC4 С ПУСТЫМИ ДАННЫМИ")
        print("=" * 80)

        key = b"TestKey"
        plaintext = b""

        rc4_enc = RC4()
        rc4_enc.setup_keys(key)
        ciphertext = rc4_enc.encrypt(plaintext)

        rc4_dec = RC4()
        rc4_dec.setup_keys(key)
        decrypted = rc4_dec.decrypt(ciphertext)

        print(f"  Пустые данные: {'✓' if plaintext == decrypted else '✗'}")
        self.assertEqual(plaintext, decrypted)
        self.assertEqual(len(ciphertext), 0)

    def test_rc4_file_encryption(self):
        """Тест шифрования файлов."""
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ ШИФРОВАНИЯ ФАЙЛОВ RC4")
        print("=" * 80)

        encrypted_dir = r"/crypto/files/encrypted"
        decrypted_dir = r"/crypto/files/decrypted"

        reset_dir(encrypted_dir)
        reset_dir(decrypted_dir)

        # Тестовый файл
        test_file = r"/crypto/files/img.png"

        if not os.path.exists(test_file):
            # Создаём тестовый файл
            os.makedirs(os.path.dirname(test_file), exist_ok=True)
            with open(test_file, "wb") as f:
                f.write(secrets.token_bytes(50 * 1024))  # 50 KB

        key_lengths = [8, 16, 32, 64]

        for key_len in key_lengths:
            key = secrets.token_bytes(key_len)
            file_name = os.path.basename(test_file)
            file_size = os.path.getsize(test_file)

            print(f"\n{'═' * 80}")
            print(f"Файл: {file_name} ({file_size:,} байт), ключ: {key_len} байт")
            print(f"{'═' * 80}")

            encrypted_file = os.path.join(
                encrypted_dir, f"rc4_{key_len}_{file_name}.enc"
            )
            decrypted_file = os.path.join(
                decrypted_dir, f"rc4_{key_len}_decrypted_{file_name}"
            )

            # Шифрование
            t1 = time.perf_counter()
            with open(test_file, "rb") as fin, open(encrypted_file, "wb") as fout:
                data = fin.read()
                rc4_enc = RC4()
                rc4_enc.setup_keys(key)
                encrypted_data = rc4_enc.encrypt(data)
                fout.write(encrypted_data)
            t_enc = time.perf_counter() - t1

            # Расшифрование
            t2 = time.perf_counter()
            with open(encrypted_file, "rb") as fin, open(decrypted_file, "wb") as fout:
                encrypted_data = fin.read()
                rc4_dec = RC4()
                rc4_dec.setup_keys(key)
                decrypted_data = rc4_dec.decrypt(encrypted_data)
                fout.write(decrypted_data)
            t_dec = time.perf_counter() - t2

            # Проверка
            with open(test_file, "rb") as f_orig, open(decrypted_file, "rb") as f_decr:
                original = f_orig.read()
                decrypted = f_decr.read()

            encrypted_size = os.path.getsize(encrypted_file)
            match = original == decrypted
            status = "✓ SUCCESS" if match else "✗ FAILED"

            print(
                f"  RC4-{key_len*8}: {status:10s} | "
                f"Размер(зашифр): {encrypted_size:10,} | "
                f"t_enc={t_enc:.3f}s t_dec={t_dec:.3f}s"
            )

            self.assertTrue(
                match,
                f"Файл не совпадает после расшифровки: {file_name} (ключ {key_len} байт)",
            )

        print("\n" + "=" * 80)
        print("Тестирование RC4 завершено.")
        print("=" * 80)

    def test_rc4_invalid_key_length(self):
        """Тест с недопустимой длиной ключа."""
        print("\n" + "=" * 80)
        print("RC4 С НЕДОПУСТИМОЙ ДЛИНОЙ КЛЮЧА")
        print("=" * 80)

        invalid_keys = [b"", b"\x00" * 257]  # 0 байт и 257 байт

        for key in invalid_keys:
            rc4 = RC4()
            with self.assertRaises(ValueError):
                rc4.setup_keys(key)
            print(f"  Ключ {len(key)} байт: ✓ корректно отклонён")

    def test_rc4_multiple_encryptions(self):
        """Тест: несколько шифрований подряд с одним ключом."""
        print("\n" + "=" * 80)
        print("RC4 НЕСКОЛЬКО ШИФРОВАНИЙ С ОДНИМ КЛЮЧОМ")
        print("=" * 80)

        key = b"MultipleTest"
        plaintexts = [
            b"Message 1",
            b"Message 2",
            b"Message 3",
        ]

        for i, pt in enumerate(plaintexts, 1):
            rc4_enc = RC4()
            rc4_enc.setup_keys(key)
            ct = rc4_enc.encrypt(pt)

            rc4_dec = RC4()
            rc4_dec.setup_keys(key)
            decrypted = rc4_dec.decrypt(ct)

            match = pt == decrypted
            print(f"  Сообщение {i}: {'✓' if match else '✗'}")
            self.assertEqual(pt, decrypted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
