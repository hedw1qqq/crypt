import secrets
from enum import Enum
from typing import Tuple, Optional

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

    class PublicKey:
        def __init__(self, n: mpz, e: mpz):
            self.n = n
            self.e = e

        def __repr__(self):
            return f"<RSA.PublicKey n_bits={self.n.bit_length()} e={self.e}>"

    class PrivateKey:
        def __init__(self, n: mpz, d: mpz):
            self.n = n
            self.d = d

        def __repr__(self):
            return f"<RSA.PrivateKey n_bits={self.n.bit_length()} d=***>"

    class RSAGenerate:
        def __init__(
            self,
            test_enum,
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
            """Защита от атаки Ферма: abs(p - q) > n^{1/4}"""
            return abs(p - q) ** 4 > p * q

        def _check_wiener_safe(self, n: mpz, d: mpz) -> bool:
            """Защита от атаки Винера: d > n^{1/4}"""
            return d**4 > n

        def _select_e_d(self, phi: mpz) -> tuple[mpz, mpz]:
            e_candidate = mpz(self.e)
            if NumberService.gcd(e_candidate, phi) == 1:
                g, x, _ = NumberService.extended_gcd(e_candidate, phi)
                if g == 1:
                    d = x % phi
                    return e_candidate, d

            while True:
                cand = mpz(secrets.randbits(17) | 1)
                if cand < 7 or cand >= phi:
                    continue
                if NumberService.gcd(cand, phi) != 1:
                    continue
                g, x, _ = NumberService.extended_gcd(cand, phi)
                if g == 1:
                    d = x % phi
                    return cand, d

        def generate(self) -> Tuple["RSA.PublicKey", "RSA.PrivateKey"]:
            half = self.bit_length // 2
            while True:
                p = self._gen_prime(half)
                q = self._gen_prime(self.bit_length - half)

                if p == q:
                    continue

                if not self._check_fermat_safe(p, q):
                    continue

                n = p * q
                if n.bit_length() != self.bit_length:
                    continue

                phi = (p - 1) * (q - 1)
                e, d = self._select_e_d(phi)

                if (e * d) % phi != 1:
                    continue

                if not self._check_wiener_safe(n, d):
                    continue

                if NumberService.gcd(e, phi) != 1:
                    continue

                return RSA.PublicKey(n, e), RSA.PrivateKey(n, d)

    def __init__(
        self,
        bit_length: int,
        min_probability: float,
        test: PrimalityTest,
        e: int = 65537,
    ):
        self.generator = self.RSAGenerate(test, min_probability, bit_length, e)
        self._public_key: Optional[RSA.PublicKey] = None
        self._private_key: Optional[RSA.PrivateKey] = None
        self.regenerate_keys()

    def regenerate_keys(self):
        self._public_key, self._private_key = self.generator.generate()

    @property
    def public_key(self) -> "PublicKey":
        return self._public_key

    @property
    def private_key(self) -> "PrivateKey":
        return self._private_key

    def encrypt_int(self, m: int) -> int:
        m_mpz = mpz(m)
        if m_mpz >= self.public_key.n:
            raise ValueError("Message too large for RSA modulus")
        return int(NumberService.mod_pow(m_mpz, self.public_key.e, self.public_key.n))

    # Аналог s.Decrypt(c) в Go
    def decrypt_int(self, c: int) -> int:
        c_mpz = mpz(c)
        return int(NumberService.mod_pow(c_mpz, self.private_key.d, self.private_key.n))
