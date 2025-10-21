# feistel_correct_test.py
from crypto.utility.utility import xor_bytes

def simple_F(R, key):
    return xor_bytes(R, key)

# ========== ШИФРОВАНИЕ ==========
L = b'AAAA'
R = b'BBBB'
key1 = b'KEY1'
key2 = b'KEY2'

print("=== ENCRYPTION ===")
print(f"L0: {L.hex()}, R0: {R.hex()}")

# Раунд 1
temp = xor_bytes(L, simple_F(R, key1))  # L ⊕ F(R, K1)
L = R                                    # L1 = R0
R = temp                                 # R1 = L0 ⊕ F(R0, K1)
print(f"L1: {L.hex()}, R1: {R.hex()}")

# Раунд 2
temp = xor_bytes(L, simple_F(R, key2))  # L1 ⊕ F(R1, K2)
L = R                                    # L2 = R1
R = temp                                 # R2 = L1 ⊕ F(R1, K2)
print(f"L2: {L.hex()}, R2: {R.hex()}")

# Сохраняем зашифрованное
cipher_L, cipher_R = L, R
print(f"Ciphertext: {cipher_L.hex()}{cipher_R.hex()}")

# ========== ДЕШИФРОВАНИЕ ==========
print("\n=== DECRYPTION ===")
L = cipher_L
R = cipher_R
print(f"L2: {L.hex()}, R2: {R.hex()}")

# Раунд 1 дешифрования (используем key2)
temp = xor_bytes(L, simple_F(R, key2))  # L2 ⊕ F(R2, K2)
L = R                                    # L1 = R2
R = temp                                 # R1 = L2 ⊕ F(R2, K2)
print(f"L1: {L.hex()}, R1: {R.hex()}")

# Раунд 2 дешифрования (используем key1)
temp = xor_bytes(L, simple_F(R, key1))  # L1 ⊕ F(R1, K1)
L = R                                    # L0 = R1
R = temp                                 # R0 = L1 ⊕ F(R1, K1)
print(f"L0: {L.hex()}, R0: {R.hex()}")

# Проверка
print(f"\n=== RESULT ===")
print(f"Original: L=41414141, R=42424242")
print(f"Recovered: L={L.hex()}, R={R.hex()}")
print(f"Match: {L == b'AAAA' and R == b'BBBB'}")
