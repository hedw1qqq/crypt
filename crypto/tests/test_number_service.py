import unittest
from gmpy2 import mpz, gcd as mpz_gcd
from crypto.services.number_service import NumberService


class TestLegendreSymbol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ СИМВОЛА ЛЕЖАНДРА")
        print("=" * 80)

    def test_basic_cases(self):
        print("\nТестирование базовых случаев символа Лежандра:")
        test_cases = [
            (2, 7, 1, "2 является квадратичным вычетом по модулю 7"),
            (3, 7, -1, "3 НЕ является квадратичным вычетом по модулю 7"),
            (5, 11, 1, "5 является квадратичным вычетом по модулю 11"),
            (2, 5, -1, "2 НЕ является квадратичным вычетом по модулю 5"),
            (0, 7, 0, "0 делится на 7, результат 0"),
            (10, 7, -1, "10 ≡ 3 (mod 7), не квадратичный вычет"),
        ]
        for a, p, expected, explanation in test_cases:
            result = NumberService.legendre_symbol(mpz(a), mpz(p))
            print(f"  ({a}/{p}) = {result} - {explanation}")
            self.assertEqual(result, expected)

    def test_large_numbers(self):
        print("\nТест символа Лежандра на больших числах:")
        a = mpz(12345678901234567890)
        p = mpz(1000000007)
        result = NumberService.legendre_symbol(a, p)
        print(f"  Вычисление ({a}/{p})")
        print(f"  Результат: {result}")
        self.assertIn(result, (-1, 0, 1))


class TestJacobiSymbol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ СИМВОЛА ЯКОБИ")
        print("=" * 80)

    def test_basic_cases(self):
        print("\nТестирование базовых случаев символа Якоби:")
        test_cases = [
            (1, 1, 1, "Якоби(1/1) всегда равен 1"),
            (2, 15, 1, "Якоби(2/15) для составного модуля 15"),
            (3, 5, -1, "Якоби(3/5) совпадает с Лежандром для простого 5"),
            (5, 9, 1, "Якоби(5/9) для составного модуля 9"),
            (6, 15, 0, "gcd(6,15) = 3 ≠ 1, результат 0"),
            (1001, 9907, -1, "Якоби для больших взаимно простых чисел"),
        ]
        for a, n, expected, explanation in test_cases:
            result = NumberService.jacobi_symbol(mpz(a), mpz(n))
            print(f"  ({a}/{n}) = {result} - {explanation}")
            self.assertEqual(result, expected)

    def test_legendre_consistency(self):
        print("\nПроверка: Якоби совпадает с Лежандром для простого модуля:")
        p = mpz(7)
        print(f"  Простой модуль p = {p}")
        for a in range(1, 7):
            leg = NumberService.legendre_symbol(mpz(a), p)
            jac = NumberService.jacobi_symbol(mpz(a), p)
            status = "✓" if leg == jac else "✗"
            print(f"  {status} a={a}: Legendre({a}/{p})={leg}, Jacobi({a}/{p})={jac}")
            self.assertEqual(leg, jac)


class TestGCD(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ АЛГОРИТМА ЕВКЛИДА (НОД)")
        print("=" * 80)

    def test_basic_cases(self):
        print("\nТестирование базовых случаев НОД:")
        test_cases = [
            (48, 18, 6, "НОД для взаимно делимых чисел"),
            (100, 35, 5, "НОД с общим делителем 5"),
            (17, 19, 1, "НОД двух простых чисел = 1"),
            (0, 5, 5, "НОД(0, n) = n"),
            (-48, 18, 6, "НОД работает с отрицательными числами"),
            (270, 192, 6, "НОД больших чисел"),
        ]
        for a, b, expected, explanation in test_cases:
            result = NumberService.gcd(mpz(a), mpz(b))
            print(f"  gcd({a}, {b}) = {result} - {explanation}")
            self.assertEqual(result, expected)

    def test_large_numbers(self):
        print("\nТест НОД на больших числах:")
        a = mpz(123456789012345678901234567890)
        b = mpz(987654321098765432109876543210)
        result = NumberService.gcd(a, b)
        expected = mpz_gcd(a, b)
        print(f"  Числа длиной ~{len(str(a))} цифр")
        print(f"  gcd = {result}")
        self.assertEqual(result, expected)


class TestExtendedGCD(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ РАСШИРЕННОГО АЛГОРИТМА ЕВКЛИДА")
        print("=" * 80)

    def test_bezout_identity(self):
        print("\nПроверка уравнения Безу (ax + by = gcd(a,b)):")
        test_cases = [(48, 18), (35, 15), (17, 13), (240, 46), (-48, 18)]

        for a, b in test_cases:
            gcd, x, y = NumberService.extended_gcd(mpz(a), mpz(b))
            check = a * x + b * y
            print(f"  {a}·({x}) + {b}·({y}) = {check} (gcd={gcd}) ✓")
            self.assertEqual(check, gcd)
            self.assertGreaterEqual(gcd, 0)

    def test_modular_inverse(self):
        print("\nВычисление мультипликативного обратного элемента:")
        a, m = 7, 26
        gcd, x, y = NumberService.extended_gcd(mpz(a), mpz(m))
        print(f"  Ищем обратный элемент для {a} по модулю {m}")
        self.assertEqual(gcd, 1)
        inv = x % m
        print(f"  {a}⁻¹ ≡ {inv} (mod {m})")
        print(f"  Проверка: {a} · {inv} ≡ {(a * inv) % m} (mod {m}) ✓")
        self.assertEqual((a * inv) % m, 1)


class TestModPow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 80)
        print("ТЕСТИРОВАНИЕ ВОЗВЕДЕНИЯ В СТЕПЕНЬ ПО МОДУЛЮ")
        print("=" * 80)

    def test_basic_cases(self):
        print("\nТестирование базовых случаев модульного возведения:")
        test_cases = [
            (2, 10, 1000, 24, "2^10 mod 1000"),
            (3, 7, 10, 7, "3^7 mod 10"),
            (5, 3, 13, 8, "5^3 mod 13"),
            (2, 100, 1000, 376, "2^100 mod 1000 (большая степень)"),
        ]
        for base, exp, mod, expected, explanation in test_cases:
            result = NumberService.mod_pow(mpz(base), mpz(exp), mpz(mod))
            print(f"  {explanation} = {result}")
            self.assertEqual(result, expected)

    def test_rsa_sizes(self):
        print("\nТесты на RSA размерах ключей:")

        # RSA-1024
        print("  RSA-1024 (1024-битный модуль):")
        base = mpz(2**1023 + 1)
        exp = mpz(65537)
        mod = mpz(2**1024 - 1)
        result = NumberService.mod_pow(base, exp, mod)
        print(f"    Результат имеет {len(str(result))} цифр")
        self.assertTrue(0 <= result < mod)

        # RSA-2048
        print("  RSA-2048 (2048-битный модуль):")
        base = mpz(123456789) * mpz(10**600)
        exp = mpz(10**100)
        mod = mpz(10**617)
        result = NumberService.mod_pow(base, exp, mod)
        print(f"    Результат имеет {len(str(result))} цифр")
        self.assertTrue(0 <= result < mod)

        # RSA-4096
        print("  RSA-4096 (4096-битный модуль):")
        base = mpz(2**4095)
        exp = mpz(2**512)
        mod = mpz(2**4096 - 1)
        result = NumberService.mod_pow(base, exp, mod)
        print(f"    Результат имеет {len(str(result))} цифр")
        self.assertTrue(0 <= result < mod)

    def test_extreme_exponent(self):
        print("\nТест с экстремально большой степенью:")
        base = mpz(7)
        exp = mpz(10**1000)
        mod = mpz(10**9 + 7)
        result = NumberService.mod_pow(base, exp, mod)
        print(f"  7^(10^1000) mod (10^9+7) = {result}")
        print(f"  Степень имеет {len(str(exp))} цифр!")
        self.assertTrue(0 <= result < mod)

    def test_fermat_little_theorem(self):
        print("\nПроверка малой теоремы Ферма (a^(p-1) ≡ 1 mod p):")
        p = mpz(1000000007)
        a = mpz(123456789)
        result = NumberService.mod_pow(a, p - 1, p)
        print(f"  {a}^({p}-1) mod {p} = {result}")
        print(f"  Теорема выполняется ✓")
        self.assertEqual(result, 1)

    def test_bitcoin_key_size(self):
        print("\nТест на размере Bitcoin ключа (256-бит):")
        base = mpz(2**255 + 19)
        exp = mpz(2**256 - 1)
        mod = mpz(2**256 - 2**32 - 977)
        result = NumberService.mod_pow(base, exp, mod)
        print(f"  Вычисление на 256-битных числах")
        print(f"  Результат: {result}")
        self.assertTrue(0 <= result < mod)


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=False)
