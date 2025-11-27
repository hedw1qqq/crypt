from gmpy2 import mpz
from crypto.attack.wiener_attack import WienerAttackService
from crypto.cipher_primitives.rsa.not_save_rsa import UnSaveRsa
from crypto.cipher_primitives.rsa.rsa import RSA
from crypto.services.number_service import NumberService


def demo_unsave_rsa():
    print("\n" + "=" * 60)
    print(" DEMO: UNSAFE RSA (VULNERABLE TO WIENER ATTACK) ")
    print("=" * 60)

    print("init unsafe rsa (1024 bit)...")
    unsafe_service = UnSaveRsa(
        bit_length=1024,
        min_probability=0.9999,
        test=UnSaveRsa.PrimalityTest.MILLER_RABIN,
    )

    pub_key = unsafe_service.public_key
    priv_key = unsafe_service.private_key

    print(f"[key info]")
    print(f"  n bits: {pub_key.n.bit_length()}")
    print(f"  e: {pub_key.e}")
    print(f"  d: {priv_key.d} ")

    attacker = WienerAttackService()
    print("\n[attack start]")

    result = attacker.attack(pub_key.n, pub_key.e)

    print(f"  convergents checked: {len(result.convergents)}")

    if result.d is not None:
        print("\n[SUCCESS] key found")
        print(f"  found d: {result.d}")
        print(f"  real d:  {priv_key.d}")

        if result.d == priv_key.d:
            print("  match: yes")
        else:
            print("  match: no (weird)")

        msg = b"Secret Message: Wiener Attack Works!"
        print(f"\n[verifying key]")
        print(f"  original msg: {msg}")

        m_int = int.from_bytes(msg, byteorder="big")
        c_int = unsafe_service.encrypt_int(m_int)

        k = (pub_key.n.bit_length() + 7) // 8
        ciphertext = c_int.to_bytes(k, byteorder="big")
        print(f"  ciphertext: {ciphertext.hex()[:64]}...")

        # m = c^d mod n
        m_hacked = NumberService.mod_pow(mpz(c_int), result.d, pub_key.n)

        decrypted_bytes = int(m_hacked).to_bytes(
            (m_hacked.bit_length() + 7) // 8, "big"
        )

        print(f"  hacked msg: {decrypted_bytes}")
        assert decrypted_bytes == msg
        print("  decryption ok")
    else:
        print("\n[FAIL] key not found")


def demo_save_rsa():
    print("\n" + "=" * 60)
    print(" DEMO: SAFE RSA (WIENER RESISTANT) ")
    print("=" * 60)

    print("init safe rsa (512 bit)...")
    safe_service = RSA(
        bit_length=512, min_probability=0.9999, test=RSA.PrimalityTest.MILLER_RABIN
    )

    pub_key = safe_service.public_key
    priv_key = safe_service.private_key

    print(f"[key info]")
    print(f"  n bits: {pub_key.n.bit_length()}")
    print(f"  e: {pub_key.e}")
    print(f"  d: {priv_key.d}")

    attacker = WienerAttackService()
    print("\n[attack start]")

    result = attacker.attack(pub_key.n, pub_key.e)

    print(f"  convergents checked: {len(result.convergents)}")

    if result.d is None:
        print("\n[SUCCESS] attack failed (as expected)")
        print("  wiener attack needs small d")
    else:
        print(f"\nunluck((( {result.d}")


if __name__ == "__main__":
    demo_unsave_rsa()
    demo_save_rsa()
