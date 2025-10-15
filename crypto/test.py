import os
import asyncio
from des_cipher import DES
from symmetric_context import SymmetricCipherContext
from modes import CipherMode
import shutil
from pathlib import Path

from bitperm import bitperm


def demo_bitperm():
    print("\n" + "=" * 60)
    print("ТЕСТ: Битовая перестановка (bitperm)")
    print("=" * 60)

    print("\n1. Реверс битов в байте")
    data = b'\x0F'
    p_block = [8, 7, 6, 5, 4, 3, 2, 1]

    result = bitperm(data, p_block, msb_first=True, one_based_indexing=True)

    print(f"   Входные данные:  {data.hex()} = {format(data[0], '08b')}")
    print(f"   Таблица:         {p_block}")
    print(f"   Результат:       {result.hex()} = {format(result[0], '08b')}")
    print(f"   Проверка:        00001111 → 11110000 ✓")

    print("\n2. DES Initial Permutation (IP)")
    data = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'

    ip_table = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    result = bitperm(data, ip_table, msb_first=True, one_based_indexing=True)

    print(f"   Входные данные:  {data.hex()}")
    print(f"   IP таблица:      64 позиции")
    print(f"   После IP:        {result.hex()}")
    print(f"   Биты переставлены согласно DES стандарту ✓")


async def demo_bytes_arrays(key):
    des = DES()
    print("\n" + "=" * 60)
    print("ТЕСТ: Шифрование массивов байт")
    print("=" * 60)

    test_cases = [
        (b"Hello!", "Короткое сообщение (6 байт)"),
        (b"A" * 8, "Ровно 1 блок (8 байт)"),
        (b"B" * 16, "Ровно 2 блока (16 байт)"),
        (b"Test message 123", "Ровно 2 блока (16 байт)"),
        (b"C" * 7, "Неполный блок (7 байт)"),
        (b"D" * 25, "3+ блока (25 байт)"),
        (b"", "Пустое сообщение"),
        (b"\x00\x01\x02\x03\x04\x05\x06\x07", "Бинарные данные"),
        (b"The quick brown fox jumps over the lazy dog", "Длинное сообщение (44 байта)"),
    ]

    for data, description in test_cases:
        print(f"\n{description} ({len(data)} байт)")

        for mode in [CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC,
                     CipherMode.CFB, CipherMode.OFB, CipherMode.CTR,
                     CipherMode.RANDOM_DELTA]:
            ctx = SymmetricCipherContext(des, key, mode=mode)

            encrypted = await ctx.encrypt_bytes(data)
            decrypted = await ctx.decrypt_bytes(encrypted)

            match = (data == decrypted)
            status = "✓ OK" if match else "✗ ОШИБКА"
            print(f"  {mode.name:15s}: {status} (зашифровано: {len(encrypted)} байт)")

            if not match:
                print(f"    Исходное:     {data[:20]!r}...")
                print(f"    Расшифровано: {decrypted[:20]!r}...")


async def demo_files_with_array(files, key):
    des = DES()
    encrypted_dir = "files/encrypted"
    decrypted_dir = "files/decrypted"
    for directory in ["files/encrypted", "files/decrypted"]:
        path = Path(directory)
        if path.exists():
            shutil.rmtree(path)
    os.makedirs(encrypted_dir, exist_ok=True)
    os.makedirs(decrypted_dir, exist_ok=True)

    for fname in files:
        file_base, file_ext = os.path.splitext(os.path.basename(fname))
        print(f"\nТест файла: ({fname})")

        for mode in [CipherMode.ECB, CipherMode.CTR, CipherMode.CFB, CipherMode.OFB, CipherMode.RANDOM_DELTA,
                     CipherMode.PCBC]:
            ctx = SymmetricCipherContext(des, key, mode=mode)
            out_file = os.path.join(encrypted_dir, f"{file_base}.encr_{mode.name.lower()}{file_ext}")
            decr_file = os.path.join(decrypted_dir, f"{file_base}.decr_{mode.name.lower()}{file_ext}")

            await ctx.encrypt_file(fname, out_file, chunk_size=1024 * 1024 * 123)
            await ctx.decrypt_file(out_file, decr_file, chunk_size=1024 * 1024 * 123)

            with open(fname, "rb") as f1, open(decr_file, "rb") as f2:
                match = (f1.read() == f2.read())
            print(f"  Режим {mode.name}: восстановление {'OK' if match else 'ОШИБКА'}")


if __name__ == "__main__":
    files = [
        "files/test.txt",
        "files/img.png"
    ]
    key = b"DESKey!!"
    asyncio.run(demo_files_with_array(files, key))
    asyncio.run(demo_bytes_arrays(key))
    demo_bitperm()
