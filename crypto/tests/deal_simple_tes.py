import os
import asyncio
import secrets
import shutil
import time
import unittest
from itertools import product
from pathlib import Path

from crypto.cipher_primitives.DEAL.deal_cipher import DEAL
from crypto.utility.modes import CipherMode, PaddingMode
from crypto.utility.symmetric_context import SymmetricCipherContext


def format_bytes_hex(data, bytes_per_line=16):
    hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        chunk = hex_str[i : i + bytes_per_line * 2]
        formatted = " ".join(chunk[j : j + 2] for j in range(0, len(chunk), 2))
        lines.append(f"    {formatted}")
    return "\n".join(lines)


class TestDEALCopied(unittest.TestCase):
    def test_deal_basic(self):
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ АЛГОРИТМА DEAL")
        print("=" * 80)

        test_cases = [
            (128, "DEAL-128 (6 раундов)"),
            (192, "DEAL-192 (6 раундов)"),
            (256, "DEAL-256 (8 раундов)"),
        ]

        for key_size, description in test_cases:
            print(f"\n{'─' * 80}")
            print(f"{description}")
            print(f"{'─' * 80}")

            deal = DEAL(key_size=key_size)
            key = secrets.token_bytes(key_size // 8)

            print(f"Ключ ({len(key)} байт): {key.hex()}")

            plaintext = b"DEAL Test Block!"
            print(f"\nОткрытый текст: {plaintext}")
            print(f"Hex: {plaintext.hex()}")

            deal.setup_keys(key)
            ciphertext = deal.encrypt_block(plaintext)
            decrypted = deal.decrypt_block(ciphertext)

            print(f"\nЗашифрованный (hex): {ciphertext.hex()}")
            print(f"Расшифрованный: {decrypted}")
            print(f"Hex: {decrypted.hex()}")

            match = plaintext == decrypted
            status = "✓ SUCCESS" if match else "✗ FAILED"
            print(f"\nРезультат: {status}")

            self.assertTrue(match, "ОШИБКА: Данные не совпадают!")

    def test_deal_with_modes(self):
        print("\n" + "=" * 80)
        print("DEAL С РЕЖИМАМИ ШИФРОВАНИЯ")
        print("=" * 80)

        async def _run():
            deal = DEAL(key_size=128)
            key = secrets.token_bytes(16)

            modes = [
                CipherMode.ECB,
                CipherMode.CBC,
                CipherMode.CTR,
                CipherMode.CFB,
                CipherMode.OFB,
            ]

            data_sizes = [16, 32, 64, 100]

            for size in data_sizes:
                data = secrets.token_bytes(size)
                print(f"\n{'─' * 80}")
                print(f"Тестовые данные: {size} байт")
                print(f"{'─' * 80}")

                for mode in modes:
                    ctx = SymmetricCipherContext(deal, key, mode=mode, max_workers=1)

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
            print("ТЕСТИРОВАНИЕ ШИФРОВАНИЯ ФАЙЛОВ")
            print("=" * 80)

            for directory in [encrypted_dir, decrypted_dir]:
                path = Path(directory)
                if path.exists():
                    shutil.rmtree(path)
                os.makedirs(path, exist_ok=True)

            modes = [
                CipherMode.ECB,
                # CipherMode.CBC,
                # CipherMode.PCBC,
                # CipherMode.CFB,
                # CipherMode.OFB,
                # CipherMode.CTR,
                # CipherMode.RANDOM_DELTA
            ]
            keys = [128, 192, 256]
            paddings = [
                # PaddingMode.ZEROS,
                # PaddingMode.ANSI_X923,
                PaddingMode.PKCS7,
                # PaddingMode.ISO_10126,
            ]

            files = [
                r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\img.png",
                #r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\img_1.png",
            ]

            for fname, key_bits in product(files, keys):
                if not os.path.exists(fname):
                    print(f"Файл {fname} не найден — пропуск.")
                    continue

                key_bytes = secrets.token_bytes(key_bits // 8)
                file_name = os.path.basename(fname)
                file_size = os.path.getsize(fname)

                print(f"\n{'═' * 80}")
                print(f"Файл: {file_name} ({file_size:,} байт), ключ: {key_bits} бит")
                print(f"{'═' * 80}")

                for mode, pad in product(modes, paddings):
                    deal = DEAL(key_size=key_bits)
                    ctx = SymmetricCipherContext(
                        deal, key_bytes, mode=mode, padding=pad
                    )

                    encrypted_file = os.path.join(
                        encrypted_dir, f"{mode.name.lower()}_{key_bits}_{file_name}"
                    )
                    decrypted_file = os.path.join(
                        decrypted_dir,
                        f"{mode.name.lower()}_{key_bits}_decrypted_{file_name}",
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
                        f"Файл не совпадает после расшифровки: {file_name} ({mode.name}, {pad.name})",
                    )

            print("\n" + "=" * 80)
            print("Тестирование завершено.")
            print("=" * 80)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main(verbosity=2)
