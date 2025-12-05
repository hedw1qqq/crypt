import pytest
from crypto.services.galois_service import GField, ReducibleModulusError



@pytest.mark.parametrize(
    "a,b,expected",
    [
        (0x53, 0xCA, 0x99),
        (0xFF, 0xFF, 0x00),
        (0x00, 0xAB, 0xAB),
        (0x1FF, 0x02, (0xFF ^ 0x02) & 0xFF),
    ],
)
def test_add(a, b, expected):
    res = GField.add(a, b)
    print(f"[ADD] {a:02X} + {b:02X} = {res:02X} (Expected: {expected:02X})")
    assert res == expected


@pytest.mark.parametrize(
    "poly,expected",
    [
        (0x11B, True),  # AES
        (0x100, False),  # x^8
        (0x11D, True),
    ],
)
def test_is_irreducible_deg8(poly, expected):
    res = GField.is_irreducible_deg8(poly)
    print(f"[IRR] Poly {poly:03X} irreducible? {res} (Expected: {expected})")
    assert res == expected


def test_get_all_irreducibles_deg8():
    irr = GField.get_all_irreducibles_deg8()
    print(f"[ALL_IRR] Найдено {len(irr)} неприводимых полиномов ст.8 (Ожидаем 30)")
    assert len(irr) == 30
    # Проверка первых трех для примера
    print(f"   Примеры: {[hex(x) for x in irr[:3]]} ...")
    for p in irr:
        assert (p >> 8) == 1
        assert (p & 1) == 1
        assert GField.is_irreducible_deg8(p)


@pytest.mark.parametrize(
    "a,b,mod,expected",
    [
        (0x00, 0xAE, 0x11B, 0x00),
        (0x01, 0xAE, 0x11B, 0xAE),
        (0x53, 0xCA, 0x11B, 0x01),  # Пересчитано: 53*CA mod 11B = 9E
        (0x57, 0x13, 0x11B, 0xFE),
    ],
)
def test_multiply(a, b, mod, expected):
    # Если expected вычисляется динамически в параметрах, лучше проверить пересчетом внутри
    # Но здесь 0x53 * 0xCA реально дает 0x9E в GF(2^8) по модулю AES
    # GField.multiply(0xCA, 0x53, 0x11B) вернет то же самое

    res = GField.multiply(a, b, mod)
    print(
        f"[MUL] {a:02X} * {b:02X} (mod {mod:X}) = {res:02X} (Expected: {expected:02X})"
    )

    # Если expected задан явно - проверяем
    # Если это динамический вызов в тесте - можно просто сверить коммутативность
    if expected is not None:
        assert res == expected

    # Проверка коммутативности
    res_comm = GField.multiply(b, a, mod)
    assert res == res_comm


def test_multiply_bad_modulus():
    print("[MUL_ERR] Проверка ошибки приводимого модуля...")
    with pytest.raises(ReducibleModulusError):
        GField.multiply(0x02, 0x03, 0x100)
    print("   ОК (Ошибка поймана)")


def test_inverse_basic():
    mod = 0x11B
    print(f"[INV] Проверка обратных элементов (mod {mod:X})")

    # 0
    with pytest.raises(ValueError):
        GField.inverse(0x00, mod)

    cases = [0x01, 0x02, 0x53, 0xCA]
    for a in cases:
        inv = GField.inverse(a, mod)
        prod = GField.multiply(a, inv, mod)
        print(f"   inv({a:02X}) = {inv:02X} -> check: {a:02X}*{inv:02X}={prod:02X}")
        assert prod == 0x01


def test_factorize_composite():
    print("[FACT] Факторизация составного полинома")
    p1 = 0b1011  # x^3+x+1
    p2 = 0b10011  # x^4+x+1
    comp = GField._poly_mul_no_mod(p1, p2)

    factors = GField.factorize(comp)
    print(f"   Poly {comp:b} ({comp}) -> Factors: {[bin(x) for x in factors]}")

    assert sorted(factors) == sorted([p1, p2])

