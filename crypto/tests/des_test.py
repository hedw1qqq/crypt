import os
import asyncio
import secrets

import shutil
from pathlib import Path

from crypto.DES.des_cipher import DES
from crypto.utility.modes import CipherMode
from crypto.utility.symmetric_context import SymmetricCipherContext


def format_bytes_hex(data, bytes_per_line=16):
    hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        chunk = hex_str[i : i + bytes_per_line * 2]
        formatted = " ".join(chunk[j : j + 2] for j in range(0, len(chunk), 2))
        lines.append(f"    {formatted}")
    return "\n".join(lines)


async def test_byte_sequences(key):
    des = DES()

    print("\n" + "=" * 80)
    print("ТЕСТИРОВАНИЕ ШИФРОВАНИЯ ПСЕВДОСЛУЧАЙНЫХ ПОСЛЕДОВАТЕЛЬНОСТЕЙ БАЙТОВ")
    print("=" * 80)

    test_sizes = [8, 16, 64]

    modes = [
        CipherMode.ECB,
        CipherMode.CBC,
        CipherMode.PCBC,
        CipherMode.CFB,
        CipherMode.OFB,
        CipherMode.CTR,
        CipherMode.RANDOM_DELTA,
    ]

    for size in test_sizes:
        data = secrets.token_bytes(size)

        print(f"\n{'═' * 80}")
        print(f"Псевдослучайная последовательность: {size} байт")
        print(f"{'═' * 80}")
        print("\nИсходные данные (hex):")
        print(format_bytes_hex(data))

        for mode in modes:
            ctx = SymmetricCipherContext(des, key, mode=mode)
            encrypted = await ctx.encrypt_bytes(data)
            decrypted = await ctx.decrypt_bytes(encrypted)

            match = data == decrypted
            status = "✓" if match else "✗"

            print(f"\n  Режим {mode.name}:")
            print(
                f"    Статус: {status} | Оригинал: {len(data)} байт → Зашифровано: {len(encrypted)} байт"
            )
            print(f"    Зашифрованные данные (hex):")
            print(format_bytes_hex(encrypted))

            if not match:
                print(f"    ✗ ОШИБКА РАСШИФРОВКИ!")


async def test_file_encryption(files, key):
    des = DES()
    encrypted_dir = "../files/encrypted"
    decrypted_dir = "../files/decrypted"

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

    for fname in files:
        file_name = os.path.basename(fname)
        file_size = os.path.getsize(fname)

        print(f"\n{'═' * 80}")
        print(f"Файл: {file_name} ({file_size:,} байт)")
        print(f"{'═' * 80}")

        for mode in modes:
            ctx = SymmetricCipherContext(des, key, mode=mode)

            encrypted_file = os.path.join(
                encrypted_dir, f"{mode.name.lower()}_{file_name}"
            )
            decrypted_file = os.path.join(
                decrypted_dir, f"{mode.name.lower()}_decrypted_{file_name}"
            )

            await ctx.encrypt_file(fname, encrypted_file, chunk_size=1024 * 1024)
            await ctx.decrypt_file(
                encrypted_file, decrypted_file, chunk_size=1024 * 1024
            )

            with open(fname, "rb") as f_orig:
                original = f_orig.read()
            with open(decrypted_file, "rb") as f_decr:
                decrypted = f_decr.read()

            match = original == decrypted
            encrypted_size = os.path.getsize(encrypted_file)
            status = "✓ SUCCESS" if match else "✗ FAILED"

            print(
                f"  {mode.name:15s}: {status:12s} | "
                f"Encrypted: {encrypted_size:8,} байт | "
                f"Восстановлено: {len(decrypted):8,} байт"
            )


async def demo_comprehensive_test():
    print("\n" + "╔" + "═" * 78 + "╗")
    print("║" + "DES ШИФРОВАНИЕ: КОМПЛЕКСНОЕ ТЕСТИРОВАНИЕ".center(78) + "║")
    print("╚" + "═" * 78 + "╝")

    key = b"DESKey!!"

    await test_byte_sequences(key)

    test_files = ["../files/test.txt", "../files/img.png", "../files/IMG_1217.HEIC"]

    await test_file_encryption(test_files, key)

    print("\n" + "╔" + "═" * 78 + "╗")
    print("║" + "ТЕСТИРОВАНИЕ ЗАВЕРШЕНО".center(78) + "║")
    print("╚" + "═" * 78 + "╝\n")


if __name__ == "__main__":
    asyncio.run(demo_comprehensive_test())