from gmpy2 import mpz


class NumberService:
    @staticmethod
    def legendre_symbol(a: mpz, p: mpz):
        if p < 3 or p % 2 == 0:
            raise ValueError("p must be odd prime")
        if a % p == 0:
            return 0
        quad_residue = NumberService.mod_pow(a, (p - 1) // 2, p)
        return 1 if quad_residue == 1 else -1

    @staticmethod
    def jacobi_symbol(a: mpz, n: mpz) -> int:
        if n <= 0 or n % 2 == 0:
            raise ValueError("n must be a positive odd integer")

        a = a % n
        result = 1

        while a != 0:
            while a % 2 == 0:
                a //= 2
                if n % 8 in (3, 5):
                    result = -result

            a, n = n, a

            if a % 4 == 3 and n % 4 == 3:
                result = -result

            a = a % n

        return result if n == 1 else 0

    @staticmethod
    def gcd(a: mpz, b: mpz) -> mpz:
        a, b = abs(a), abs(b)
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: mpz, b: mpz) -> tuple[mpz, mpz, mpz]:
        """:return (gcd, x, y) где ax + by = gcd(a, b)"""

        if b == 0:
            return abs(a), mpz(1) if a >= 0 else mpz(-1), mpz(0)

        sign_a = mpz(1) if a >= 0 else mpz(-1)
        sign_b = mpz(1) if b >= 0 else mpz(-1)
        a, b = abs(a), abs(b)

        old_r, r = a, b
        old_s, s = mpz(1), mpz(0)
        old_t, t = mpz(0), mpz(1)

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_r, old_s * sign_a, old_t * sign_b

    @staticmethod
    def mod_pow(val: mpz, exp: mpz, mod: mpz) -> mpz:
        if mod <= 0:
            raise ValueError("Modulus must be positive")
        if exp < 0:
            raise ValueError("pow must be non-negative")
        res: mpz = mpz(1)
        val %= mod
        while exp > 0:
            if exp % 2 == 1:
                res = (res * val) % mod
            val = (val * val) % mod
            exp >>= 1
        return res % mod
