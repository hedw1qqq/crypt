from gmpy2 import mpz
import math
from crypto.primality_tests.base_primality_test import BasePrimalityTest
from crypto.services.number_service import NumberService


class MillerRabinTest(BasePrimalityTest):
    def get_required_rounds(self, min_probability: float) -> int:
        return math.ceil((-math.log(1 - min_probability, 4)))

    def _test_iteration(self, n: mpz) -> bool:

        s, t = self._factor_out_twos(n - 1)

        a = self._generate_random_witness(n)

        x = NumberService.mod_pow(a, t, n)

        if x == 1 or x == n - 1:
            return True

        for _ in range(s - 1):
            x = NumberService.mod_pow(x, mpz(2), n)

            if x == n - 1:
                return True

            if x == 1:
                return False

        return False

    def _factor_out_twos(self, n_minus_1: mpz) -> tuple[int, mpz]:
        s = 0
        t = n_minus_1
        while t % 2 == 0:
            s += 1
            t //= 2
        return s, t
