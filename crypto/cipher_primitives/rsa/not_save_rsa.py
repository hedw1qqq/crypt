import secrets
from enum import Enum
from typing import Tuple, Optional
from gmpy2 import mpz

# Предполагаем, что эти импорты работают так же
from crypto.primality_tests.fermat_test import FermatTest
from crypto.primality_tests.miller_rabin_test import MillerRabinTest
from crypto.primality_tests.solovay_strassen_test import SolovayStrassenTest
from crypto.services.number_service import NumberService


class UnSaveRsa:
    """
    Реализация RSA, НАМЕРЕННО уязвимая к атаке Винера (Small Private Exponent Attack).
    Генерирует очень маленький приватный ключ d.
    """

    class PrimalityTest(Enum):
        FERMAT = 1
        SOLOVAY_STRASSEN = 2
        MILLER_RABIN = 3

    # --- Явные классы ключей (аналогично безопасному классу) ---
    class PublicKey:
        def __init__(self, n: mpz, e: mpz):
            self.n = n
            self.e = e

        def __repr__(self):
            return f"<UnSaveRsa.PublicKey n_bits={self.n.bit_length()} e={self.e}>"

    class PrivateKey:
        def __init__(self, n: mpz, d: mpz):
            self.n = n
            self.d = d

        def __repr__(self):
            # Показываем d, так как для UnSaveRsa это критически важный параметр (он маленький)
            return f"<UnSaveRsa.PrivateKey n_bits={self.n.bit_length()} d={self.d} (VULNERABLE)>"

    class RSAGenerate:
        def __init__(
            self,
            test_enum,
            min_probability: float,
            bit_length: int,
            e: int = 65537,  # Этот параметр здесь игнорируется в пользу генерации малого d
        ):
            self.test_enum = test_enum
            self.min_probability = min_probability
            self.bit_length = bit_length
            # self.e не сохраняем, так как e будет вычисляться на основе d

            if not (0.5 <= min_probability < 1.0):
                raise ValueError("min_probability must be in [0.5, 1)")
            if bit_length < 512:
                raise ValueError("bit_length must be >= 512")

            if test_enum == UnSaveRsa.PrimalityTest.FERMAT:
                self.test_prime = FermatTest()
            elif test_enum == UnSaveRsa.PrimalityTest.SOLOVAY_STRASSEN:
                self.test_prime = SolovayStrassenTest()
            elif test_enum == UnSaveRsa.PrimalityTest.MILLER_RABIN:
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

        def _select_vulnerable_d_and_e(self, phi: mpz) -> tuple[mpz, mpz]:
            """
            Генерирует пару (e, d), где d - очень маленькое число (уязвимость Винера).
            """
            while True:

                d = mpz(secrets.randbits(16) | 1)

                if d < 3:
                    continue

                if NumberService.gcd(d, phi) != 1:
                    continue

                # e * d = 1 (mod phi)
                g, x, _ = NumberService.extended_gcd(d, phi)
                if g != 1:
                    continue

                e = x % phi
                if e <= 1:
                    continue

                return e, d

        def generate(self) -> Tuple["UnSaveRsa.PublicKey", "UnSaveRsa.PrivateKey"]:
            half = self.bit_length // 2
            while True:
                p = self._gen_prime(half)
                q = self._gen_prime(self.bit_length - half)
                if p == q:
                    continue

                n = p * q
                if n.bit_length() != self.bit_length:
                    continue

                phi = (p - 1) * (q - 1)

                e, d = self._select_vulnerable_d_and_e(phi)

                if (e * d) % phi != 1:
                    continue

                return UnSaveRsa.PublicKey(n, e), UnSaveRsa.PrivateKey(n, d)

    def __init__(
        self,
        bit_length: int,
        min_probability: float,
        test: PrimalityTest,
        e: int = 65537,
    ):
        self.generator = self.RSAGenerate(test, min_probability, bit_length, e)
        self._public_key: Optional[UnSaveRsa.PublicKey] = None
        self._private_key: Optional[UnSaveRsa.PrivateKey] = None
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

