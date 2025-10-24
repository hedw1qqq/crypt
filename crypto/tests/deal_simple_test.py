import asyncio
import hashlib
import os
import secrets
import shutil
import time
from itertools import product
from pathlib import Path

from crypto.DEAL.deal_cipher import DEAL
from crypto.utility.modes import CipherMode, PaddingMode
from crypto.utility.symmetric_context import SymmetricCipherContext


def test_deal_basic():
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

        if not match:
            print("ОШИБКА: Данные не совпадают!")


async def test_deal_with_modes():
    print("\n" + "=" * 80)
    print("DEAL С РЕЖИМАМИ ШИФРОВАНИЯ")
    print("=" * 80)

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


async def test_file_encryption(files):
    encrypted_dir = "C:\\Users\\ivglu\\Desktop\\crypt\\crypt\\crypto\\files\\encrypted"
    decrypted_dir = "C:\\Users\\ivglu\\Desktop\\crypt\\crypt\\crypto\\files\\decrypted"
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
        CipherMode.CBC,
        CipherMode.PCBC,
        CipherMode.CFB,
        CipherMode.OFB,
        CipherMode.CTR,
        CipherMode.RANDOM_DELTA,
    ]
    keys = [128, 192, 256]
    paddings = [
        PaddingMode.ZEROS,
        PaddingMode.ANSI_X923,
        PaddingMode.PKCS7,
        PaddingMode.ISO_10126,
    ]
    for fname, key in product(files, keys):
        if not os.path.exists(fname):
            print(f"Файл {fname} не найден — пропуск.")
            continue

        key_bytes = os.urandom(key // 8)
        file_name = os.path.basename(fname)
        file_size = os.path.getsize(fname)

        print(f"\n{'═' * 80}")
        print(f"Файл: {file_name} ({file_size:,} байт), ключ: {key} бит")
        print(f"{'═' * 80}")

        for mode, pad in product(modes, paddings):
            deal = DEAL(key_size=key)
            ctx = SymmetricCipherContext(deal, key_bytes, mode=mode, padding=pad)

            encrypted_file = os.path.join(
                encrypted_dir, f"{mode.name.lower()}_{key}_{file_name}"
            )
            decrypted_file = os.path.join(
                decrypted_dir, f"{mode.name.lower()}_{key}_decrypted_{file_name}"
            )

            t1 = time.perf_counter()
            await ctx.encrypt_file(fname, encrypted_file, chunk_size=1024 * 1024)
            t_enc = time.perf_counter() - t1

            t2 = time.perf_counter()
            await ctx.decrypt_file(
                encrypted_file, decrypted_file, chunk_size=1024 * 1024
            )
            t_dec = time.perf_counter() - t2

            with open(fname, "rb") as f_orig, open(decrypted_file, "rb") as f_decr:
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

            if not match:
                print("    Ошибка: файл после расшифровки не совпадает с исходным!")

    print("\n" + "=" * 80)
    print("Тестирование завершено.")
    print("=" * 80)


if __name__ == "__main__":
    test_deal_basic()
    asyncio.run(test_deal_with_modes())
    asyncio.run(test_file_encryption(["C:\\Users\\ivglu\\Desktop\\crypt\\crypt\\crypto\\files\\img.png"]))
