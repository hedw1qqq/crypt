# Временный тестовый файл для отладки
from crypto.DEAL.deal_cipher import DEAL
from crypto.DES.des_cipher import DES

# Простой тест без режимов
deal = DEAL(key_size=128)
key = b'A' * 16  # Простой ключ для отладки

plaintext = b'DEAL Test Block!'  # 16 байт
print(f"Plaintext: {plaintext.hex()}")

deal.setup_keys(key)

# Добавим отладочный вывод в encrypt/decrypt
encrypted = deal.encrypt_block(plaintext)
print(f"Encrypted: {encrypted.hex()}")

decrypted = deal.decrypt_block(encrypted)
print(f"Decrypted: {decrypted.hex()}")
print(f"Match: {plaintext == decrypted}")

# Проверка что DES сам по себе работает
des = DES()
des.setup_keys(b'TESTKEY!')
test_block = b'12345678'
enc = des.encrypt_block(test_block)
dec = des.decrypt_block(enc)
print(f"\nDES check: {test_block == dec}")
