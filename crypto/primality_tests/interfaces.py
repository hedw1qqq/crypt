from abc import ABC, abstractmethod
from gmpy2 import mpz


class IPrimalityTest(ABC):
    @abstractmethod
    def is_prime(self, n: mpz, min_probability: float = 0.99) -> bool:
        pass

    @abstractmethod
    def get_required_rounds(self, min_probability: float) -> int:
        pass
