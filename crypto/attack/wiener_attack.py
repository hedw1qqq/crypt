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
    """
    Stateless-сервис атаки Винера.
    Функционал:
      - Построение цепной дроби e/n
      - Генерация подходящих дробей (convergents) из цепной дроби
      - Поиск приватного показателя d и φ(n) через проверку кандидатов k/d

    Результат:
      - d (если найдено) или None
      - phi_n (если найдено) или None
      - список всех подходящих дробей (k_i, d_i) для e/n
    """

    def attack(self, n: mpz, e: mpz) -> WienerAttackResult:
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
            # s = n - phi + 1, дискриминант: D = s^2 - 4n
            s = n - phi_candidate + 1
            D = s * s - 4 * n
            if D < 0:
                continue

            if not isqrt(D):
                continue

            t = isqrt(D)
            # Восстановить p, q и проверить корректность
            p = (s + t) // 2
            q = (s - t) // 2
            if p <= 0 or q <= 0:
                continue
            if p * q != n:
                continue

            # Нашли корректные p, q => возвращаем d и phi
            return WienerAttackResult(mpz(d), mpz(phi_candidate), convs)

        # Не удалось найти (не уязвим по Винеру)
        return WienerAttackResult(None, None, convs)

    def _continued_fraction(self, numerator: mpz, denominator: mpz) -> list[int]:
        """
        Строит конечную цепную дробь для рационального числа numerator/denominator.
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
        Генерирует все подходящие дроби p_i/q_i из коэффициентов цепной дроби.
        Возвращает список (k_i, d_i) == (p_i, q_i).
        """
        convs: List[Tuple[mpz, mpz]] = []
        # Инициализация:
        # p[-2]=0, p[-1]=1; q[-2]=1, q[-1]=0
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
