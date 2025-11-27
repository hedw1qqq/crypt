# tests/test_triple_des.py

import os
import asyncio
import secrets
import shutil
import time
import unittest
from itertools import product

from crypto.cipher_primitives.DES.triple_des import TripleDES
from crypto.utility.modes import CipherMode, PaddingMode
from crypto.utility.symmetric_context import (
    SymmetricCipherContext,
)


def reset_dir(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)


def format_bytes_hex(data, bytes_per_line=16):
    hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        chunk = hex_str[i : i + bytes_per_line * 2]
        formatted = " ".join(chunk[j : j + 2] for j in range(0, len(chunk), 2))
        lines.append(f"    {formatted}")
    return "\n".join(lines)


class TestTripleDES(unittest.TestCase):
    def test_3des_basic(self):
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ АЛГОРИТМА 3DES (EDE/EEE)")
        print("=" * 80)

        cases = [
            ("EDE", b"\x01" * 8 + b"\x02" * 8),  # 16 байт
            ("EEE", b"\x0A" * 8 + b"\x0B" * 8),  # 16 байт
            ("EDE", b"\x11" * 8 + b"\x22" * 8 + b"\x33" * 8),  # 24 байта
            ("EEE", b"\xAA" * 8 + b"\xBB" * 8 + b"\xCC" * 8),  # 24 байта
        ]

        for mode_name, key in cases:
            print(f"\n{'─' * 80}")
            print(f"TripleDES {mode_name} | ключ {len(key)} байт")
            print(f"{'─' * 80}")

            tdes = TripleDES(mode=mode_name)
            tdes.setup_keys(key)

            plaintext = b"ABCDEFGH"
            print(f"\nОткрытый текст: {plaintext!r}")
            print(f"Hex:\n{format_bytes_hex(plaintext)}")

            ciphertext = tdes.encrypt_block(plaintext)
            decrypted = tdes.decrypt_block(ciphertext)

            print(f"\nЗашифрованный (hex):\n{format_bytes_hex(ciphertext)}")
            print(f"Расшифрованный: {decrypted!r}")
            print(f"Hex:\n{format_bytes_hex(decrypted)}")

            match = plaintext == decrypted
            status = "✓ SUCCESS" if match else "✗ FAILED"
            print(f"\nРезультат: {status}")

            self.assertTrue(
                match, f"Несовпадение для режима {mode_name} (len(key)={len(key)})"
            )

    def test_3des_with_modes(self):
        print("\n" + "=" * 80)
        print("3DES С РЕЖИМАМИ ШИФРОВАНИЯ (ECB/CBC)")
        print("=" * 80)

        async def _run():
            tdes_template = TripleDES(mode="EEE")  # шаблон примитива
            key = b"\x01" * 8 + b"\x02" * 8 + b"\x03" * 8  # 24 байта

            modes = [
                CipherMode.ECB,
                CipherMode.CBC,
                CipherMode.PCBC,
                CipherMode.RANDOM_DELTA,
                CipherMode.CTR,
            ]
            data_sizes = [17, 33, 63, 101]

            for size in data_sizes:
                data = secrets.token_bytes(size)
                print(f"\n{'─' * 80}")
                print(f"Тестовые данные: {size} байт")
                print(f"{'─' * 80}")

                for mode in modes:
                    tdes = TripleDES(mode="EEE")

                    iv = None
                    if mode == CipherMode.CBC:
                        iv = secrets.token_bytes(8)

                    # Свежий контекст для шифрования
                    ctx = SymmetricCipherContext(
                        tdes,
                        key,
                        mode=mode,
                        padding=PaddingMode.PKCS7,
                        iv=iv,
                        max_workers=1,
                    )

                    encrypted = await ctx.encrypt_bytes(data)
                    decrypted = await ctx.decrypt_bytes(encrypted)

                    match = data == decrypted
                    status = "✓" if match else "✗"

                    print(
                        f"  {mode.name:10s}: {status} | "
                        f"Оригинал: {size:3d} байт → "
                        f"Зашифровано: {len(encrypted):3d} байт"
                    )

                    self.assertTrue(
                        match, f"Расшифровка не совпала для режима {mode.name}"
                    )

        asyncio.run(_run())

    def test_file_encryption(self):
        async def _run():
            encrypted_dir = r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\encrypted"
            decrypted_dir = r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\decrypted"
            os.makedirs("../files", exist_ok=True)

            print("\n" + "=" * 80)
            print("ТЕСТИРОВАНИЕ ШИФРОВАНИЯ ФАЙЛОВ 3DES")
            print("=" * 80)

            reset_dir(encrypted_dir)
            reset_dir(decrypted_dir)

            modes = [
                CipherMode.ECB,
                CipherMode.CBC,
                CipherMode.PCBC,
                CipherMode.CFB,
                CipherMode.OFB,
                CipherMode.CTR,
                CipherMode.RANDOM_DELTA,
            ]
            paddings = [
                PaddingMode.PKCS7,
            ]

            keys_3des = [
                ("EEE", b"\x01" * 8 + b"\x02" * 8),  # 16 байт (K3=K1)
                ("EDE", b"\x0A" * 8 + b"\x0B" * 8),  # 16 байт (K3=K1)
                ("EEE", b"\x11" * 8 + b"\x22" * 8 + b"\x33" * 8),  # 24 байта
                ("EDE", b"\xAA" * 8 + b"\xBB" * 8 + b"\xCC" * 8),  # 24 байта
            ]

            files = [
                r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\img.png",
            ]

            for fname, (mode_name, key_bytes) in product(files, keys_3des):
                if not os.path.exists(fname):
                    print(f"Файл {fname} не найден — пропуск.")
                    continue

                file_name = os.path.basename(fname)
                file_size = os.path.getsize(fname)

                print(f"\n{'═' * 80}")
                print(
                    f"Файл: {file_name} ({file_size:,} байт), 3DES={mode_name}, ключ {len(key_bytes)} байт"
                )
                print(f"{'═' * 80}")

                for mode, pad in product(modes, paddings):
                    tdes = TripleDES(mode=mode_name)
                    ctx = SymmetricCipherContext(
                        tdes, key_bytes, mode=mode, padding=pad
                    )

                    encrypted_file = os.path.join(
                        encrypted_dir,
                        f"{mode.name.lower()}_{mode_name.lower()}_{file_name}.enc",
                    )
                    decrypted_file = os.path.join(
                        decrypted_dir,
                        f"{mode.name.lower()}_{mode_name.lower()}_decrypted_{file_name}",
                    )

                    t1 = time.perf_counter()
                    await ctx.encrypt_file(
                        fname, encrypted_file, chunk_size=1024 * 1024
                    )
                    t_enc = time.perf_counter() - t1

                    t2 = time.perf_counter()
                    await ctx.decrypt_file(
                        encrypted_file, decrypted_file, chunk_size=1024 * 1024
                    )
                    t_dec = time.perf_counter() - t2

                    with open(fname, "rb") as f_orig, open(
                        decrypted_file, "rb"
                    ) as f_decr:
                        original = f_orig.read()
                        decrypted = f_decr.read()

                    encrypted_size = os.path.getsize(encrypted_file)

                    match = original == decrypted
                    status = "✓ SUCCESS" if match else "✗ FAILED"

                    print(
                        f"  {pad.name} | {mode.name:15s}: {status:10s} | "
                        f"Размер(зашифр): {encrypted_size:10,} | "
                        f"t_enc={t_enc:.3f}s t_dec={t_dec:.3f}s"
                    )

                    self.assertTrue(
                        match,
                        f"Файл не совпадает после расшифровки: {file_name} (3DES-{mode_name}, {mode.name}, {pad.name})",
                    )

            print("\n" + "=" * 80)
            print("Тестирование 3DES завершено.")
            print("=" * 80)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main(verbosity=2)
