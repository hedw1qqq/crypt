import secrets

from gmpy2 import mpz

from crypto.primality_tests.interfaces import IPrimalityTest
from crypto.services.number_service import NumberService
from crypto.primality_tests.miller_rabin_test import MillerRabinTest


class DiffieHellman:
    class GenerateNumbers:

        @staticmethod
        def get_random_bits(bits: int) -> mpz:
            return mpz(secrets.randbits(bits))

        @staticmethod
        def generate_prime(bits: int, primality_test: IPrimalityTest) -> mpz:

            while True:

                candidate = DiffieHellman.GenerateNumbers.get_random_bits(bits)
                candidate |= 1
                candidate |= 1 << (bits - 1)

                if primality_test.is_prime(candidate):
                    return candidate

        @staticmethod
        def generate_safe_prime_parameters(
            bits: int, primality_test: IPrimalityTest
        ) -> tuple[mpz, mpz]:

            p = DiffieHellman.GenerateNumbers.generate_prime(bits, primality_test)

            while True:
                g = DiffieHellman.GenerateNumbers.get_random_bits(bits - 1)
                if 2 <= g < p:
                    return p, g

    def __init__(self, bit_length: int = 256):
        self.bit_length = bit_length
        self.primality_test = MillerRabinTest()
        self.p: mpz = mpz(0)
        self.g: mpz = mpz(0)
        self._private_key: mpz = mpz(0)
        self.public_key: mpz = mpz(0)

    def generate_parameters(self):
        self.p, self.g = DiffieHellman.GenerateNumbers.generate_safe_prime_parameters(
            self.bit_length, self.primality_test
        )
        return self.p, self.g

    def set_parameters(self, p: mpz, g: mpz):
        """Установка параметров (для второй стороны)."""
        self.p = p
        self.g = g

    def generate_keys(self) -> mpz:
        """ Генерация приватного и публичного ключей."""
        if self.p == 0:
            raise ValueError("Параметры p и g не установлены.")

        self._private_key = DiffieHellman.GenerateNumbers.get_random_bits(
            self.bit_length - 1
        )

        self.public_key = NumberService.mod_pow(self.g, self._private_key, self.p)
        return self.public_key

    def compute_shared_secret(self, other_public_key: mpz) -> mpz:
        shared_secret = NumberService.mod_pow(
            other_public_key, self._private_key, self.p
        )
        return shared_secret
