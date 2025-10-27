from gmpy2 import mpz
import math
from crypto.primality_tests.base_primality_test import BasePrimalityTest
from crypto.services.number_service import NumberService


class SolovayStrassenTest(BasePrimalityTest):
    def get_required_rounds(self, min_probability: float) -> int:
        return math.ceil((-math.log(1 - min_probability, 2)))

    def _test_iteration(self, n: mpz) -> bool:
        a = self._generate_random_witness(n)
        if NumberService.gcd(a, n) != 1:
            return False

        res = NumberService.mod_pow(a, (n - 1) // 2, n)
        jacobi = NumberService.jacobi_symbol(a, n) % n

        return res == jacobi
