import os
import asyncio
from des_cipher import DES
from symmetric_context import SymmetricCipherContext
from modes import CipherMode
import shutil
from pathlib import Path

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

        for mode in [CipherMode.ECB, CipherMode.CTR]:
            ctx = SymmetricCipherContext(des, key, mode=mode)
            out_file = os.path.join(encrypted_dir, f"{file_base}.encr_{mode.name.lower()}{file_ext}")
            decr_file = os.path.join(decrypted_dir, f"{file_base}.decr_{mode.name.lower()}{file_ext}")

            await ctx.encrypt_file(fname, out_file, chunk_size=4096)
            await ctx.decrypt_file(out_file, decr_file, chunk_size=4096)

            with open(fname, "rb") as f1, open(decr_file, "rb") as f2:
                match = (f1.read() == f2.read())
            print(f"  Режим {mode.name}: восстановление {'OK' if match else 'ОШИБКА'}")


if __name__ == "__main__":
    files = [
        "files/test.txt",
        "files/IMG_1217.HEIC"
    ]
    key = b"DESKey!!"  # 8 байт ключ
    asyncio.run(demo_files_with_array(files, key))
