# crypto/attack/wiener_attack.py

from gmpy2 import mpz, isqrt
from typing import List, Tuple, Optional


class WienerAttackResult:
    def __init__(
        self, d: Optional[mpz], phi_n: Optional[mpz], convergents: List[Tuple[mpz, mpz]]
    ) -> None:
        self.d = d
        self.phi_n = phi_n
        self.convergents = convergents

    def __repr__(self) -> str:
        return f"WienerAttackResult(d={self.d}, phi_n={self.phi_n}, convergents_len={len(self.convergents)})"


class WienerAttackService:

    def attack(self, n: mpz, e: mpz) -> WienerAttackResult:
        """

        e * d - k * ф(n) = 1
        ф(n) = (ed-1) / k
        e/ф(n) - k/d = 1/(d * ф(n))

        """
        n = mpz(n)
        e = mpz(e)

        cf = self._continued_fraction(e, n)
        convs = self._convergents(cf)

        for k, d in convs:
            if k == 0:
                continue
            # Проверка, что (e*d - 1) делится на k => phi = (e*d - 1) / k — кандидат на φ(n)
            ed_minus_1 = e * d - 1
            if ed_minus_1 % k != 0:
                continue

            phi_candidate = ed_minus_1 // k
            # квадратное уравнение (x-p)(x-q) = x^2 - (p+q)x + pq
            # p + q = n - ф(n) + 1
            s = n - phi_candidate + 1
            D = s * s - 4 * n

            if D < 0:
                continue
            t = isqrt(D)
            if t * t != D:
                continue

            # проверяем p, q
            p = (s + t) // 2
            q = (s - t) // 2
            if p <= 0 or q <= 0:
                continue
            if p * q != n:
                continue

            return WienerAttackResult(mpz(d), mpz(phi_candidate), convs)

        return WienerAttackResult(None, None, convs)

    def _continued_fraction(self, numerator: mpz, denominator: mpz) -> list[int]:
        """
        Строит конечную цепную дробь для рационального числ
        """
        a: list[int] = []
        n = mpz(numerator)
        d = mpz(denominator)
        if d == 0:
            raise ZeroDivisionError("denominator must be non-zero")
        while d != 0:
            q = n // d
            a.append(int(q))
            n, d = d, n - q * d
        return a

    def _convergents(self, cf: list[int]) -> List[Tuple[mpz, mpz]]:
        """
        Генерирует все подходящие дроби из коэффициентов цепной дроби.
        Возвращает список (k_i, d_i) == (p_i, q_i).
        """
        convs: List[Tuple[mpz, mpz]] = []

        p_prev2, p_prev1 = mpz(0), mpz(1)
        q_prev2, q_prev1 = mpz(1), mpz(0)

        for a_i in cf:
            a = mpz(a_i)
            p = a * p_prev1 + p_prev2
            q = a * q_prev1 + q_prev2
            convs.append((mpz(p), mpz(q)))
            p_prev2, p_prev1 = p_prev1, p
            q_prev2, q_prev1 = q_prev1, q

        return convs
