import os
import shutil
import asyncio
import unittest
from pathlib import Path

from crypto.cipher_primitives.DES.des_cipher import DES
from crypto.utility.modes import CipherMode
from crypto.utility.symmetric_context import SymmetricCipherContext


def format_bytes_hex(data: bytes, bytes_per_line: int = 16) -> str:
    hex_str = data.hex()
    lines = []
    for i in range(0, len(hex_str), bytes_per_line * 2):
        chunk = hex_str[i : i + bytes_per_line * 2]
        formatted = " ".join(chunk[j : j + 2] for j in range(0, len(chunk), 2))
        lines.append(f"    {formatted}")
    return "\n".join(lines)


class TestDESComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "╔" + "═" * 78 + "╗")
        print("║" + "DES ШИФРОВАНИЕ: КОМПЛЕКСНОЕ ТЕСТИРОВАНИЕ".center(78) + "║")
        print("╚" + "═" * 78 + "╝")
        cls.des = DES()
        cls.key = b"DESKey!!"
        cls.modes = [
            CipherMode.ECB,
            CipherMode.CBC,
            CipherMode.PCBC,
            CipherMode.CFB,
            CipherMode.OFB,
            CipherMode.CTR,
            CipherMode.RANDOM_DELTA,
        ]

        cls.files = [
            r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\img.png",
            r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\img_1.png",
        ]
        cls.encrypted_dir = Path(
            r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\encrypted"
        )
        cls.decrypted_dir = Path(
            r"C:\Users\ivglu\Desktop\crypt\crypt\crypto\files\decrypted"
        )

        for d in (cls.encrypted_dir, cls.decrypted_dir):
            if d.exists():
                print(f"Очищаем папку: {d}")
                shutil.rmtree(d)
            print(f"Создаём папку: {d}")
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        print("\n" + "╔" + "═" * 78 + "╗")
        print("║" + "ТЕСТИРОВАНИЕ ЗАВЕРШЕНО".center(78) + "║")
        print("╚" + "═" * 78 + "╝\n")

    def test_random_byte_sequences(self):
        print("\n" + "=" * 80)
        print("ТЕСТ: Псевдослучайные последовательности байт")
        print("=" * 80)

        async def run_case():
            sizes = [8, 16, 64]
            for size in sizes:
                data = os.urandom(size)
                print(f"\n{'═' * 80}")
                print(f"Длина последовательности: {size} байт")
                print(f"{'═' * 80}")
                print("\nИсходные данные (hex):")
                print(format_bytes_hex(data))

                for mode in self.modes:
                    ctx = SymmetricCipherContext(self.des, self.key, mode=mode)
                    encrypted = await ctx.encrypt_bytes(data)
                    decrypted = await ctx.decrypt_bytes(encrypted)

                    ok = data == decrypted
                    status = "✓" if ok else "✗"
                    print(f"\n  Режим {mode.name}:")
                    print(
                        f"    Статус: {status} | Исходник: {len(data)} байт → Шифртекст: {len(encrypted)} байт"
                    )
                    print("    Шифртекст (hex):")
                    print(format_bytes_hex(encrypted))
                    self.assertTrue(ok, f"Ошибка расшифровки в режиме {mode.name}")

        asyncio.run(run_case())

    def test_file_encryption_batch(self):
        print("\n" + "=" * 80)
        print("ТЕСТ: Шифрование/дешифрование файлов (batch)")
        print("=" * 80)

        async def run_case():
            for fname in self.files:
                src = Path(fname)
                if not src.exists():
                    print(f"[Пропуск] Нет файла: {src}")
                    continue

                file_size = src.stat().st_size
                print(f"\n{'═' * 80}")
                print(f"Файл: {src.name} ({file_size:,} байт)")
                print(f"{'═' * 80}")

                for mode in self.modes:
                    ctx = SymmetricCipherContext(self.des, self.key, mode=mode)

                    enc_path = self.encrypted_dir / f"{mode.name.lower()}_{src.name}"
                    dec_path = (
                        self.decrypted_dir / f"{mode.name.lower()}_decrypted_{src.name}"
                    )

                    await ctx.encrypt_file(
                        str(src), str(enc_path), chunk_size=1024 * 1024
                    )
                    await ctx.decrypt_file(
                        str(enc_path), str(dec_path), chunk_size=1024 * 1024
                    )

                    with open(src, "rb") as f1, open(dec_path, "rb") as f2:
                        orig = f1.read()
                        rec = f2.read()
                    ok = orig == rec
                    enc_size = enc_path.stat().st_size
                    status = "✓ УСПЕХ" if ok else "✗ ОШИБКА"
                    print(
                        f"  {mode.name:15s}: {status:10s} | "
                        f"Шифртекст: {enc_size:8,} байт | "
                        f"Восстановлено: {len(rec):8,} байт"
                    )
                    self.assertTrue(
                        ok,
                        f"Несовпадение байт после декодирования ({mode.name}): {src.name}",
                    )

        asyncio.run(run_case())


if __name__ == "__main__":
    unittest.main(verbosity=2)
