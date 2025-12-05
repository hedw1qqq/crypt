class ReducibleModulusError(ValueError):
    pass


class GField:

    @staticmethod
    def add(a: int, b: int) -> int:
        """Сложение двоичных полиномов (XOR)."""
        return (a ^ b) & 0xFF

    @staticmethod
    def multiply(a: int, b: int, modulus: int) -> int:
        """Умножение в GF(2^8) по модулю."""
        GField._ensure_irreducible(modulus)

        res = 0
        a &= 0xFF
        b &= 0xFF
        # Отбрасываем старший бит (x^8),
        poly_tail = modulus & 0xFF

        for _ in range(8):
            if (b & 1) != 0:
                res ^= a

            high_bit_set = (a & 0x80) != 0
            a = (a << 1) & 0xFF
            if high_bit_set:
                a ^= poly_tail

            b >>= 1
        return res

    @staticmethod
    def inverse(a: int, modulus: int) -> int:
        if a == 0:
            raise ValueError("Обратного элемента для 0 не существует")

        return GField._fast_pow(a, 254, modulus)

    @staticmethod
    def is_irreducible_deg8(poly: int) -> bool:
        """Проверка полинома степени 8 на неприводимость."""
        # Проверяем степень
        if poly.bit_length() - 1 != 8:
            return False

        if (poly & 1) == 0:
            return False
        SMALL_IRREDUCIBLES = GField._find_all_irreducibles_up_to_deg4()
        # Пробуем делить на все неприводимые полиномы степени <= 4
        for divisor in SMALL_IRREDUCIBLES:
            _, rem = GField._poly_divmod(poly, divisor)
            if rem == 0:
                return False

        return True

    @staticmethod
    def get_all_irreducibles_deg8() -> list[int]:
        result = []
        for poly in range(0x101, 0x200, 2):
            if GField.is_irreducible_deg8(poly):
                result.append(poly)

        return result

    @staticmethod
    def factorize(poly: int) -> list[int]:
        """Разложение произвольного полинома на неприводимые множители."""
        if poly <= 1:
            return []

        factors = []

        # Выносим множитель x (если полином четный)
        while (poly & 1) == 0:
            factors.append(0x2)  # 0x2 - x
            poly >>= 1

        if poly == 1:
            return factors

        divisor = 0x3

        while divisor * divisor <= poly:
            quotient, remainder = GField._poly_divmod(poly, divisor)

            while remainder == 0:
                factors.append(divisor)
                poly = quotient

                if poly == 1:
                    return factors

                quotient, remainder = GField._poly_divmod(poly, divisor)

            divisor += 2

        if poly > 1:
            factors.append(poly)

        return factors

    @staticmethod
    def _ensure_irreducible(modulus: int) -> None:
        """Валидация модуля."""
        # Проверка: степень 8
        if modulus.bit_length() - 1 != 8:
            raise ReducibleModulusError(f"Степень модуля 0x{modulus:X} не равна 8")

        # Проверка неприводимости
        if not GField.is_irreducible_deg8(modulus):
            raise ReducibleModulusError(f"Модуль 0x{modulus:X} приводим!")

    @staticmethod
    def _poly_mul_no_mod(a: int, b: int) -> int:
        res = 0
        while b:
            if b & 1:
                res ^= a
            a <<= 1
            b >>= 1
        return res

    @staticmethod
    def _poly_degree(n: int) -> int:
        return n.bit_length() - 1 if n > 0 else -1

    @staticmethod
    def _poly_div(u: int, v: int) -> int:
        q, _ = GField._poly_divmod(u, v)
        return q

    @staticmethod
    def _poly_divmod(u: int, v: int) -> tuple[int, int]:
        if v == 0:
            raise ZeroDivisionError()

        q = 0
        r = u
        deg_v = v.bit_length() - 1
        deg_r = r.bit_length() - 1

        while deg_r >= deg_v:
            diff = deg_r - deg_v
            q ^= 1 << diff
            r ^= v << diff
            deg_r = r.bit_length() - 1

        return q, r

    @staticmethod
    def _fast_pow(a: int, exp: int, modulus: int) -> int:
        res = 1
        base = a
        while exp > 0:
            if exp & 1:
                res = GField.multiply(res, base, modulus)
            base = GField.multiply(base, base, modulus)
            exp >>= 1
        return res

    @staticmethod
    def _find_all_irreducibles_up_to_deg4():
        irreducibles = [0x2]

        for deg in range(1, 5):
            start = 1 << deg | 1  # 2^deg
            end = 1 << (deg + 1)  # 2^(deg+1)

            for poly in range(start, end, 2):

                is_irreducible = True
                for divisor in irreducibles:
                    if (divisor.bit_length() - 1) > deg // 2:
                        break

                    _, remainder = GField._poly_divmod(poly, divisor)
                    if remainder == 0:
                        is_irreducible = False
                        break

                if is_irreducible:
                    irreducibles.append(poly)

        return irreducibles
