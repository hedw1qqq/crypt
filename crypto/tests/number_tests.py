from gmpy2 import mpz, gcd as mpz_gcd
from crypto.services.number_service import NumberService


def test_legendre_symbol():
    print("\n" + "=" * 80)
    print("ТЕСТИРОВАНИЕ СИМВОЛА ЛЕЖАНДРА")
    print("=" * 80)

    assert NumberService.legendre_symbol(mpz(2), mpz(7)) == 1, "(2/7) должно быть 1"
    assert NumberService.legendre_symbol(mpz(3), mpz(7)) == -1, "(3/7) должно быть -1"
    assert NumberService.legendre_symbol(mpz(5), mpz(11)) == 1, "(5/11) должно быть 1"
    assert NumberService.legendre_symbol(mpz(2), mpz(5)) == -1, "(2/5) должно быть -1"
    assert NumberService.legendre_symbol(mpz(0), mpz(7)) == 0, "(0/7) должно быть 0"
    assert NumberService.legendre_symbol(mpz(10), mpz(7)) == -1, "(10/7) должно быть -1"

    print("✓ Все базовые тесты пройдены")

    a = mpz(12345678901234567890)
    p = mpz(1000000007)
    result = NumberService.legendre_symbol(a, p)
    assert result in (-1, 0, 1), "Результат должен быть -1, 0 или 1"
    print(f"✓ Тест на больших числах: ({a}/{p}) = {result}")


def test_jacobi_symbol():

    print("\n" + "=" * 80)
    print("ТЕСТИРОВАНИЕ СИМВОЛА ЯКОБИ")
    print("=" * 80)

    assert NumberService.jacobi_symbol(mpz(1), mpz(1)) == 1
    assert NumberService.jacobi_symbol(mpz(2), mpz(15)) == 1
    assert NumberService.jacobi_symbol(mpz(3), mpz(5)) == -1
    assert NumberService.jacobi_symbol(mpz(5), mpz(9)) == 1
    assert NumberService.jacobi_symbol(mpz(6), mpz(15)) == 0
    assert NumberService.jacobi_symbol(mpz(1001), mpz(9907)) == -1

    print("✓ Все базовые тесты пройдены")

    p = mpz(7)
    for a in range(1, 7):
        leg = NumberService.legendre_symbol(mpz(a), p)
        jac = NumberService.jacobi_symbol(mpz(a), p)
        assert (
            leg == jac
        ), f"Для простого p={p}: Legendre({a}/{p}) должен совпадать с Jacobi({a}/{p})"

    print("✓ Проверка связи с Лежандром пройдена")


def test_gcd():

    print("\n" + "=" * 80)
    print("ТЕСТИРОВАНИЕ АЛГОРИТМА ЕВКЛИДА (НОД)")
    print("=" * 80)

    assert NumberService.gcd(mpz(48), mpz(18)) == 6
    assert NumberService.gcd(mpz(100), mpz(35)) == 5
    assert NumberService.gcd(mpz(17), mpz(19)) == 1
    assert NumberService.gcd(mpz(0), mpz(5)) == 5
    assert NumberService.gcd(mpz(-48), mpz(18)) == 6
    assert NumberService.gcd(mpz(270), mpz(192)) == 6

    print("✓ Все базовые тесты пройдены")

    a = mpz(123456789012345678901234567890)
    b = mpz(987654321098765432109876543210)
    g = NumberService.gcd(a, b)
    assert g == mpz_gcd(a,b)
    print(f"✓ Тест на больших числах: gcd = {g}")


def test_extended_gcd():

    print("\n" + "=" * 80)
    print("ТЕСТИРОВАНИЕ РАСШИРЕННОГО АЛГОРИТМА ЕВКЛИДА (УРАВНЕНИЕ БЕЗУ)")
    print("=" * 80)

    test_cases = [
        (48, 18),
        (35, 15),
        (17, 13),
        (240, 46),
        (-48, 18),
    ]

    for a, b in test_cases:
        gcd, x, y = NumberService.extended_gcd(mpz(a), mpz(b))

        check = a * x + b * y
        assert (
            check == gcd
        ), f"Уравнение Безу не выполнено: {a}*{x} + {b}*{y} = {check} ≠ {gcd}"

        assert gcd >= 0, f"НОД должен быть неотрицательным, получено {gcd}"

    print(f"✓ Все {len(test_cases)} тестов пройдены")

    a, m = 7, 26
    gcd, x, y = NumberService.extended_gcd(mpz(a), mpz(m))
    assert gcd == 1, f"Числа {a} и {m} должны быть взаимно простыми"
    inv = x % m
    assert (a * inv) % m == 1, f"Обратный элемент {inv} не корректен"
    print(f"✓ Обратный элемент: {a}⁻¹ ≡ {inv} (mod {m})")


def test_mod_pow():

    print("\n" + "=" * 80)
    print("ТЕСТИРОВАНИЕ ВОЗВЕДЕНИЯ В СТЕПЕНЬ ПО МОДУЛЮ")
    print("=" * 80)

    assert NumberService.mod_pow(mpz(2), mpz(10), mpz(1000)) == 24
    assert NumberService.mod_pow(mpz(3), mpz(7), mpz(10)) == 7
    assert NumberService.mod_pow(mpz(5), mpz(3), mpz(13)) == 8
    assert NumberService.mod_pow(mpz(2), mpz(100), mpz(1000)) == 376
    base = mpz(2**1023 + 1)
    exp = mpz(65537)
    mod = mpz(2**1024 - 1)
    result = NumberService.mod_pow(base, exp, mod)
    assert 0 <= result < mod
    print(f"✓ RSA-1024 размер: base≈2^1023, exp=65537, mod≈2^1024")
    print(f"  Результат: {str(result)[:50]}... ({len(str(result))} цифр)")


    base = mpz(123456789) * mpz(10**600)
    exp = mpz(10**100)
    mod = mpz(10**617)
    result = NumberService.mod_pow(base, exp, mod)
    assert 0 <= result < mod
    print(f"✓ RSA-2048 размер: exp≈10^100, mod≈10^617")
    print(f"  Результат: {str(result)[:50]}... ({len(str(result))} цифр)")


    base = mpz(2**4095)
    exp = mpz(2**512)
    mod = mpz(2**4096 - 1)
    result = NumberService.mod_pow(base, exp, mod)
    assert 0 <= result < mod
    print(f"✓ RSA-4096 размер: base≈2^4095, exp≈2^512, mod≈2^4096")
    print(f"  Результат: {str(result)[:50]}... ({len(str(result))} цифр)")


    base = mpz(7)
    exp = mpz(10**1000)
    mod = mpz(10**9 + 7)
    result = NumberService.mod_pow(base, exp, mod)
    assert 0 <= result < mod
    print(f"✓ Экстремальная степень: 7^(10^1000) mod (10^9+7)")
    print(f"  Результат: {result}")



    p = mpz(1000000007)
    a = mpz(123456789)
    result = NumberService.mod_pow(a, p - 1, p)
    assert result == 1, "Малая теорема Ферма нарушена"
    print(f"✓ Малая теорема Ферма: {a}^({p}-1) ≡ 1 (mod {p})")


    base = mpz(2**255 + 19)
    exp = mpz(2**256 - 1)
    mod = mpz(2**256 - 2**32 - 977)
    result = NumberService.mod_pow(base, exp, mod)
    assert 0 <= result < mod
    print(f"✓ Размер биткоин-ключа: 256-битные числа")
    print(f"  Результат: {result}")
    print("✓ Все базовые тесты пройдены")

    base = mpz(2)
    exp = mpz(1000000)
    mod = mpz(10**9 + 7)
    result = NumberService.mod_pow(base, exp, mod)
    assert 0 <= result < mod, "Результат должен быть в диапазоне [0, mod)"
    print(f"✓ Тест на больших числах: 2^{exp} mod {mod} = {result}")

    a = mpz(3)
    p = mpz(7)
    result = NumberService.mod_pow(a, p - 1, p)
    assert (
        result == 1
    ), f"Малая теорема Ферма нарушена: {a}^({p}-1) mod {p} = {result} ≠ 1"
    print(f"✓ Проверка малой теоремы Ферма: {a}^{p-1} ≡ 1 (mod {p})")


def test_performance():

    print("\n" + "=" * 80)
    print("ТЕСТ ПРОИЗВОДИТЕЛЬНОСТИ")
    print("=" * 80)

    import time

    p = mpz(2**607 - 1)
    q = mpz(2**521 - 1)

    print(f"p ≈ 2^607 - 1 ({len(str(p))} цифр)")
    print(f"q ≈ 2^521 - 1 ({len(str(q))} цифр)")

    start = time.time()
    g = NumberService.gcd(p, q)
    elapsed = time.time() - start
    assert g == 1, "Простые числа Мерсенна должны быть взаимно простыми"
    print(f"\n✓ gcd(p, q) = {g} (время: {elapsed*1000:.2f} мс)")

    base = mpz(12345)
    exp = mpz(67890)
    mod = mpz(10**9 + 7)

    start = time.time()
    result = NumberService.mod_pow(base, exp, mod)
    elapsed = time.time() - start
    assert 0 <= result < mod
    print(f"✓ {base}^{exp} mod {mod} = {result} (время: {elapsed*1000:.2f} мс)")


if __name__ == "__main__":

    try:
        test_legendre_symbol()
        test_jacobi_symbol()
        test_gcd()
        test_extended_gcd()
        test_mod_pow()
        test_performance()

        print("\n" + "=" * 80)
        print("✓ ВСЕ ТЕСТЫ УСПЕШНО ПРОЙДЕНЫ!")
        print("=" * 80)
    except AssertionError as e:
        print(f"\n✗ ТЕСТ ПРОВАЛИЛСЯ: {e}")
        raise
