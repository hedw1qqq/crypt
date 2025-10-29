import secrets
from enum import Enum
from typing import Tuple

from gmpy2 import mpz
from crypto.primality_tests.fermat_test import FermatTest
from crypto.primality_tests.miller_rabin_test import MillerRabinTest
from crypto.primality_tests.solovay_strassen_test import SolovayStrassenTest
from crypto.services.number_service import NumberService


class RSA:
    class PrimalityTest(Enum):
        FERMAT = 1
        SOLOVAY_STRASSEN = 2
        MILLER_RABIN = 3

    class RSAGenerate:
        def __init__(
            self,
            test_enum: int,
            min_probability: float,
            bit_length: int,
            e: int = 65537,
        ):
            self.test_enum = test_enum
            self.min_probability = min_probability
            self.bit_length = bit_length
            self.e = mpz(e)

            if not (0.5 <= min_probability < 1.0):
                raise ValueError("min_probability must be in [0.5, 1)")
            if bit_length < 512:
                raise ValueError("bit_length must be >= 512")

            if test_enum == RSA.PrimalityTest.FERMAT:
                self.test_prime = FermatTest()
            elif test_enum == RSA.PrimalityTest.SOLOVAY_STRASSEN:
                self.test_prime = SolovayStrassenTest()
            elif test_enum == RSA.PrimalityTest.MILLER_RABIN:
                self.test_prime = MillerRabinTest()
            else:
                raise ValueError("Unknown primality test")

        def _random_odd(self, bits: int) -> mpz:
            val = mpz(secrets.randbits(bits))
            val |= mpz(1)
            val |= mpz(1) << (bits - 1)
            return val

        def _gen_prime(self, bits: int) -> mpz:
            while True:
                cand = self._random_odd(bits)
                if self.test_prime.is_prime(cand, self.min_probability):
                    return cand

        def _check_fermat_safe(self, p: mpz, q: mpz) -> bool:
            """
            TODO: Implement Fermat factorization safety check.
            Should verify that |p - q| is large enough to prevent Fermat attacks.
            """
            ...

        def _check_wiener_safe(self, n: mpz, d: mpz) -> bool:
            """
            TODO: Implement Wiener's attack safety check.
            Should verify that d is large enough to prevent Wiener's attack.
            Typically d should be > n^0.25.
            """
            ...

        def _select_e_d(self, phi: mpz) -> Tuple[mpz, mpz]:
            """
            TODO: Implement selection of public exponent e and private exponent d.
            Should compute d as the modular inverse of e modulo phi(n).
            Must verify that gcd(e, phi) = 1.
            """
            ...

        def generate(self) -> Tuple[mpz, mpz, mpz]:
            """
            TODO: Implement RSA key generation.
            Should:
            1. Generate two distinct primes p and q
            2. Compute n = p * q
            3. Compute phi = (p-1) * (q-1)
            4. Select e and d using _select_e_d
            5. Verify safety using _check_fermat_safe and _check_wiener_safe
            6. Return (n, e, d)
            """
            ...

    def __init__(
        self,
        bit_length: int,
        min_probability: float,
        test: int,
        e: int = 65537,
    ):
        self.generator = self.RSAGenerate(test, min_probability, bit_length, e)
        self.n, self.e, self.d = self.generator.generate()

    def regenerate_keys(self):
        self.n, self.e, self.d = self.generator.generate()

    def _encrypt_int(self, m: mpz) -> mpz:
        return NumberService.mod_pow(m, self.e, self.n)

    def _decrypt_int(self, c: mpz) -> mpz:
        return NumberService.mod_pow(c, self.d, self.n)

    def encrypt_bytes(self, data: bytes) -> bytes:
        k = (self.n.bit_length() + 7) // 8
        m = mpz(int.from_bytes(data, byteorder="big"))
        c = self._encrypt_int(m)
        return int(c).to_bytes(k, "big")

    def decrypt_bytes(self, blob: bytes) -> bytes:
        k = (self.n.bit_length() + 7) // 8
        c = mpz(int.from_bytes(blob, byteorder="big"))
        m = self._decrypt_int(c)
        return int(m).to_bytes(k, "big")
