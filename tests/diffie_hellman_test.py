import asyncio
import hashlib
import os

from crypto.cipher_primitives.diffie_hellman.diffie_hellman import DiffieHellman
from crypto.cipher_primitives.rijndael.rijndael_cipher import RijndaelCipher
from crypto.utility.modes import CipherMode, PaddingMode
from crypto.utility.symmetric_context import SymmetricCipherContext


def derive_key(shared_secret_mpz, key_size_bytes=32):
    secret_bytes = str(shared_secret_mpz).encode("utf-8")
    digest = hashlib.sha256(secret_bytes).digest()

    return digest[:key_size_bytes]


async def main():
    print("=== 1. ПРОТОКОЛ ДИФФИ-ХЕЛЛМАНА ===")

    alice_dh = DiffieHellman(bit_length=128)
    p, g = alice_dh.generate_parameters()
    print(f"Параметры сети:\n  P: {p}\n  G: {g}")

    bob_dh = DiffieHellman(bit_length=128)
    bob_dh.set_parameters(p, g)

    alice_pub = alice_dh.generate_keys()
    bob_pub = bob_dh.generate_keys()
    print(f"Alice Public: {alice_pub}")
    print(f"Bob Public:   {bob_pub}")

    alice_secret = alice_dh.compute_shared_secret(bob_pub)
    bob_secret = bob_dh.compute_shared_secret(alice_pub)

    if alice_secret != bob_secret:
        print("ОШИБКА: Секреты не совпали!")
        return

    print(f"\nОбщий секрет (число): {alice_secret}")

    print("\n=== 2. СИММЕТРИЧНОЕ ШИФРОВАНИЕ (RIJNDAEL) ===")

    key_size = 32
    block_size = 16

    session_key = derive_key(alice_secret, key_size_bytes=key_size)
    print(f"Сессионный ключ (hex): {session_key.hex()}")

    primitive = RijndaelCipher(block_size=block_size, key_size=key_size)

    iv = os.urandom(block_size)

    context = SymmetricCipherContext(
        primitive=primitive,
        key=session_key,
        mode=CipherMode.CBC,
        padding=PaddingMode.PKCS7,
        iv=iv,
    )

    message = b"Secret message delivered via DH + Rijndael!"
    print(f"\nИсходное сообщение: {message}")

    encrypted_data = await context.encrypt_bytes(message)
    print(f"Зашифровано (bytes): {encrypted_data.hex()}")

    decrypt_context = SymmetricCipherContext(
        primitive=RijndaelCipher(block_size=block_size, key_size=key_size),
        key=session_key,
        mode=CipherMode.CBC,
        padding=PaddingMode.PKCS7,
        iv=iv,
    )

    decrypted_data = await decrypt_context.decrypt_bytes(encrypted_data)
    print(f"Расшифровано: {decrypted_data}")

    assert message == decrypted_data
    print("\n[SUCCESS] Цикл успешно завершен.")


if __name__ == "__main__":
    asyncio.run(main())
