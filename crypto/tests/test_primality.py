import unittest
from gmpy2 import mpz
from crypto.primality_tests.fermat_test import FermatTest
from crypto.primality_tests.solovay_strassen_test import SolovayStrassenTest
from crypto.primality_tests.miller_rabin_test import MillerRabinTest


class TestKnownPrimes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fermat = FermatTest()
        cls.solovay = SolovayStrassenTest()
        cls.miller = MillerRabinTest()
        cls.prob = 0.99
        print("\n=== Initialized Known Primes Tests ===")

    def test_small_prime_5(self):
        n = mpz(5)
        print(f"\nTesting prime n = {n}")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertTrue(all([fermat_result, solovay_result, miller_result]))

    def test_small_prime_17(self):
        n = mpz(17)
        print(f"\nTesting prime n = {n}")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertTrue(all([fermat_result, solovay_result, miller_result]))

    def test_small_prime_97(self):
        n = mpz(97)
        print(f"\nTesting prime n = {n}")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertTrue(all([fermat_result, solovay_result, miller_result]))

    def test_medium_prime_1009(self):
        n = mpz(1009)
        print(f"\nTesting prime n = {n}")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertTrue(all([fermat_result, solovay_result, miller_result]))

    def test_large_prime_10007(self):
        n = mpz(10007)
        print(f"\nTesting prime n = {n}")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertTrue(all([fermat_result, solovay_result, miller_result]))

    def test_mersenne_prime(self):
        n = mpz(2**31 - 1)
        print(f"\nTesting Mersenne prime n = 2^31 - 1 = {n}")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertTrue(all([fermat_result, solovay_result, miller_result]))


class TestKnownComposites(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fermat = FermatTest()
        cls.solovay = SolovayStrassenTest()
        cls.miller = MillerRabinTest()
        cls.prob = 0.99
        print("\n=== Initialized Known Composites Tests ===")

    def test_composite_4(self):
        n = mpz(4)
        print(f"\nTesting composite n = 4 = 2^2")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertFalse(any([fermat_result, solovay_result, miller_result]))

    def test_composite_9(self):
        n = mpz(9)
        print(f"\nTesting composite n = 9 = 3^2")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertFalse(any([fermat_result, solovay_result, miller_result]))

    def test_composite_15(self):
        n = mpz(15)
        print(f"\nTesting composite n = 15 = 3 x 5")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertFalse(any([fermat_result, solovay_result, miller_result]))

    def test_composite_221(self):
        n = mpz(221)
        print(f"\nTesting composite n = 221 = 13 x 17")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertFalse(any([fermat_result, solovay_result, miller_result]))


class TestTrivialCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.miller = MillerRabinTest()
        cls.prob = 0.99
        print("\n=== Initialized Trivial Cases Tests ===")

    def test_prime_2(self):
        n = mpz(2)
        print(f"\nTesting trivial prime n = {n}")
        result = self.miller.is_prime(n, self.prob)
        print(f"Miller-Rabin: {result}")
        self.assertTrue(result)

    def test_prime_3(self):
        n = mpz(3)
        print(f"\nTesting trivial prime n = {n}")
        result = self.miller.is_prime(n, self.prob)
        print(f"Miller-Rabin: {result}")
        self.assertTrue(result)


class TestCarmichaelNumbers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fermat = FermatTest()
        cls.solovay = SolovayStrassenTest()
        cls.miller = MillerRabinTest()
        cls.prob = 0.99
        print("\n=== Initialized Carmichael Numbers Tests ===")

    def test_carmichael_561(self):
        n = mpz(561)
        print(f"\nTesting Carmichael number n = 561 = 3 x 11 x 17")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertFalse(solovay_result)
        self.assertFalse(miller_result)

    def test_carmichael_1105(self):
        n = mpz(1105)
        print(f"\nTesting Carmichael number n = 1105 = 5 x 13 x 17")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertFalse(solovay_result)
        self.assertFalse(miller_result)

    def test_carmichael_1729(self):
        n = mpz(1729)
        print(f"\nTesting Carmichael number n = 1729 = 7 x 13 x 19")
        fermat_result = self.fermat.is_prime(n, self.prob)
        solovay_result = self.solovay.is_prime(n, self.prob)
        miller_result = self.miller.is_prime(n, self.prob)
        print(f"Fermat: {fermat_result}, Solovay-Strassen: {solovay_result}, Miller-Rabin: {miller_result}")
        self.assertFalse(solovay_result)
        self.assertFalse(miller_result)


class TestProbabilityLevels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fermat = FermatTest()
        cls.solovay = SolovayStrassenTest()
        cls.miller = MillerRabinTest()
        cls.n = mpz(104729)
        print("\n=== Initialized Probability Levels Tests ===")

    def test_probability_0_5(self):
        prob = 0.5
        print(f"\nTesting n = {self.n} with probability = {prob}")
        rounds = self.miller.get_required_rounds(prob)
        result = self.miller.is_prime(self.n, prob)
        print(f"Miller-Rabin rounds: {rounds}, result: {result}")
        self.assertTrue(result)

    def test_probability_0_75(self):
        prob = 0.75
        print(f"\nTesting n = {self.n} with probability = {prob}")
        rounds = self.miller.get_required_rounds(prob)
        result = self.miller.is_prime(self.n, prob)
        print(f"Miller-Rabin rounds: {rounds}, result: {result}")
        self.assertTrue(result)

    def test_probability_0_9(self):
        prob = 0.9
        print(f"\nTesting n = {self.n} with probability = {prob}")
        rounds = self.miller.get_required_rounds(prob)
        result = self.miller.is_prime(self.n, prob)
        print(f"Miller-Rabin rounds: {rounds}, result: {result}")
        self.assertTrue(result)

    def test_probability_0_99(self):
        prob = 0.99
        print(f"\nTesting n = {self.n} with probability = {prob}")
        rounds = self.miller.get_required_rounds(prob)
        result = self.miller.is_prime(self.n, prob)
        print(f"Miller-Rabin rounds: {rounds}, result: {result}")
        self.assertTrue(result)

    def test_probability_0_999(self):
        prob = 0.999
        print(f"\nTesting n = {self.n} with probability = {prob}")
        rounds = self.miller.get_required_rounds(prob)
        result = self.miller.is_prime(self.n, prob)
        print(f"Miller-Rabin rounds: {rounds}, result: {result}")
        self.assertTrue(result)

    def test_probability_0_9999(self):
        prob = 0.9999
        print(f"\nTesting n = {self.n} with probability = {prob}")
        rounds = self.miller.get_required_rounds(prob)
        result = self.miller.is_prime(self.n, prob)
        print(f"Miller-Rabin rounds: {rounds}, result: {result}")
        self.assertTrue(result)

    def test_rounds_comparison(self):
        prob = 0.999
        print(f"\nComparing required rounds for probability = {prob}")
        fermat_rounds = self.fermat.get_required_rounds(prob)
        solovay_rounds = self.solovay.get_required_rounds(prob)
        miller_rounds = self.miller.get_required_rounds(prob)
        print(f"Fermat: {fermat_rounds}, Solovay-Strassen: {solovay_rounds}, Miller-Rabin: {miller_rounds}")
        self.assertLessEqual(miller_rounds, fermat_rounds)
        self.assertLessEqual(miller_rounds, solovay_rounds)


class TestEdgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.miller = MillerRabinTest()
        cls.prob = 0.99
        print("\n=== Initialized Edge Cases Tests ===")

    def test_small_odd_primes(self):
        primes = [mpz(5), mpz(7), mpz(11)]
        print("\nTesting small odd primes")
        for n in primes:
            with self.subTest(n=n):
                result = self.miller.is_prime(n, self.prob)
                print(f"n = {n}: {result}")
                self.assertTrue(result)

    def test_small_odd_composites(self):
        composites = [mpz(9), mpz(15)]
        print("\nTesting small odd composites")
        for n in composites:
            with self.subTest(n=n):
                result = self.miller.is_prime(n, self.prob)
                print(f"n = {n}: {result}")
                self.assertFalse(result)

    def test_even_numbers(self):
        even_composites = [mpz(4), mpz(100), mpz(1000)]
        print("\nTesting even numbers")
        for n in even_composites:
            with self.subTest(n=n):
                result = self.miller.is_prime(n, self.prob)
                print(f"n = {n}: {result}")
                self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=False)
