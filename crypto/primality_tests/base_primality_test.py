import secrets
from abc import ABC, abstractmethod
from gmpy2 import mpz
from crypto.primality_tests.interfaces import IPrimalityTest


class BasePrimalityTest(IPrimalityTest, ABC):
    def is_prime(self, n: mpz, min_probability: float = 0.99) -> bool:
        self._validate_input(n, min_probability)

        num_rounds = self.get_required_rounds(min_probability)
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        for _ in range(num_rounds):
            if not self._test_iteration(n):
                return False

        return True

    @abstractmethod
    def _test_iteration(self, n: mpz) -> bool:
        pass

    @abstractmethod
    def get_required_rounds(self, min_probability: float) -> int:
        pass

    def _validate_input(self, n: mpz, min_probability: float) -> None:
        if n < 2:
            raise ValueError("n must be greater than 2")
        if not (0.5 <= min_probability < 1.0):
            raise ValueError("min_probability must be in range [0.5, 1.0)")

    def _generate_random_witness(self, n: mpz, mil_rob: bool = False) -> mpz:
        if mil_rob:
            end = n - 2
        else:
            end = n - 1
        bit_length = (n - 3).bit_length()
        while True:
            a = mpz(secrets.randbits(bit_length))
            if 2 <= a <= end:
                return a
