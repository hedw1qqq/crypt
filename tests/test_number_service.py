import pytest
from gmpy2 import mpz, gcd as mpz_gcd
from crypto.services.number_service import NumberService

# ТЕСТЫ СИМВОЛА ЛЕЖАНДРА


def test_legendre_basic():
    print("\n[test] legendre symbol basics")
    test_cases = [
        (2, 7, 1, "2 is QR mod 7"),
        (3, 7, -1, "3 is NOT QR mod 7"),
        (5, 11, 1, "5 is QR mod 11"),
        (2, 5, -1, "2 is NOT QR mod 5"),
        (0, 7, 0, "0 mod 7 is 0"),
        (10, 7, -1, "10 == 3 mod 7 -> -1"),
    ]
    for a, p, expected, note in test_cases:
        res = NumberService.legendre_symbol(mpz(a), mpz(p))
        print(f"  ({a}/{p}) -> {res} [{note}]")
        assert res == expected


def test_legendre_large():
    print("\n[test] legendre large numbers")
    a = mpz(12345678901234567890)
    p = mpz(1000000007)
    res = NumberService.legendre_symbol(a, p)
    print(f"  result: {res}")
    assert res in (-1, 0, 1)


# ТЕСТЫ СИМВОЛА ЯКОБ


def test_jacobi_basic():
    print("\n[test] jacobi symbol basics")
    test_cases = [
        (1, 1, 1, "(1/1) always 1"),
        (2, 15, 1, "(2/15) composite"),
        (3, 5, -1, "(3/5) prime match legendre"),
        (5, 9, 1, "(5/9) composite"),
        (6, 15, 0, "gcd(6,15)!=1 -> 0"),
    ]
    for a, n, expected, note in test_cases:
        res = NumberService.jacobi_symbol(mpz(a), mpz(n))
        print(f"  ({a}/{n}) -> {res} [{note}]")
        assert res == expected


def test_jacobi_legendre_consistency():
    print("\n[test] jacobi == legendre for primes")
    p = mpz(7)
    for a in range(1, 7):
        leg = NumberService.legendre_symbol(mpz(a), p)
        jac = NumberService.jacobi_symbol(mpz(a), p)
        print(f"  a={a}: leg={leg}, jac={jac}")
        assert leg == jac


#  ТЕСТЫ GCD


def test_gcd_basic():
    print("\n[test] gcd basics")
    test_cases = [
        (48, 18, 6),
        (100, 35, 5),
        (17, 19, 1),
        (0, 5, 5),
        (-48, 18, 6),
        (270, 192, 6),
    ]
    for a, b, expected in test_cases:
        res = NumberService.gcd(mpz(a), mpz(b))
        print(f"  gcd({a}, {b}) -> {res}")
        assert res == expected


def test_gcd_large():
    print("\n[test] gcd large numbers")
    a = mpz(123456789012345678901234567890)
    b = mpz(987654321098765432109876543210)
    res = NumberService.gcd(a, b)
    expected = mpz_gcd(a, b)
    print(f"  res: {res}")
    assert res == expected


# === ТЕСТЫ EXTENDED GCD ===


def test_bezout_identity():
    print("\n[test] bezout identity (ax + by = gcd)")
    cases = [(48, 18), (35, 15), (17, 13), (240, 46), (-48, 18)]
    for a, b in cases:
        g, x, y = NumberService.extended_gcd(mpz(a), mpz(b))
        check = a * x + b * y
        print(f"  {a}*{x} + {b}*{y} = {check} (gcd={g})")
        assert check == g
        assert g >= 0


def test_modular_inverse():
    print("\n[test] modular inverse")
    a, m = 7, 26
    g, x, y = NumberService.extended_gcd(mpz(a), mpz(m))
    assert g == 1
    inv = x % m
    print(f"  inv({a}, {m}) -> {inv}")
    assert (a * inv) % m == 1


# === ТЕСТЫ MOD POW ===


def test_mod_pow_basic():
    print("\n[test] mod pow basics")
    test_cases = [
        (2, 10, 1000, 24),
        (3, 7, 10, 7),
        (5, 3, 13, 8),
        (2, 100, 1000, 376),
    ]
    for b, e, m, expected in test_cases:
        res = NumberService.mod_pow(mpz(b), mpz(e), mpz(m))
        print(f"  {b}^{e} mod {m} -> {res}")
        assert res == expected




def test_mod_pow_fermat():
    print("\n[test] fermat little theorem check")
    p = mpz(1000000007)
    a = mpz(123456789)
    res = NumberService.mod_pow(a, p - 1, p)
    print(f"  {a}^(p-1) mod p -> {res}")
    assert res == 1
