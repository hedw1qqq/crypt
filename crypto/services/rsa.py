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
        MillerRabinTest = 3

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
            elif test_enum == RSA.PrimalityTest.MillerRabinTest:
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

        def _check_fermat_safe(self, p: mpz, q: mpz) -> bool: ...

        def _check_wiener_safe(self, n: mpz, d: mpz) -> bool: ...

        def _select_e_d(self, phi: mpz) -> Tuple[mpz, mpz]: ...

        def generate(self) -> Tuple[mpz, mpz, mpz]: ...

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
