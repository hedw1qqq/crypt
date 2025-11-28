import pytest
from gmpy2 import mpz
from crypto.primality_tests.fermat_test import FermatTest
from crypto.primality_tests.solovay_strassen_test import SolovayStrassenTest
from crypto.primality_tests.miller_rabin_test import MillerRabinTest


@pytest.fixture(scope="module")
def tests():
    print("\n[setup] init primality tests")
    return {
        "fermat": FermatTest(),
        "solovay": SolovayStrassenTest(),
        "miller": MillerRabinTest(),
    }


@pytest.fixture
def prob():
    return 0.99


def check_prime(tests_dict, n, probability, expected=True):
    n_mpz = mpz(n)
    results = {}
    for name, test_obj in tests_dict.items():

        res = test_obj.is_prime(n_mpz, probability)
        results[name] = res

    print(f"  n={n}: {results}")

    assert results["miller"] == expected
    assert results["solovay"] == expected


def test_known_primes(tests, prob):
    print("\n[test] known primes")
    primes = [2, 3, 5, 17, 97, 1009, 10007, 2**31 - 1]
    for p in primes:
        check_prime(tests, p, prob, expected=True)


def test_known_composites(tests, prob):
    print("\n[test] known composites")
    composites = [4, 9, 15, 221, 100, 1000]
    for c in composites:
        check_prime(tests, c, prob, expected=False)


def test_carmichael_numbers(tests, prob):
    print("\n[test] carmichael numbers (fermat should fail)")

    carmichaels = [561, 1105, 29341]

    for c in carmichaels:
        n = mpz(c)
        f_res = tests["fermat"].is_prime(n, prob)
        s_res = tests["solovay"].is_prime(n, prob)
        m_res = tests["miller"].is_prime(n, prob)

        print(f"  n={c}: fermat={f_res}, solovay={s_res}, miller={m_res}")

        assert s_res is False
        assert m_res is False


def test_probability_levels(tests):
    print("\n[test] probability levels & rounds")
    n = mpz(104729)  # Prime
    probs = [0.5, 0.75, 0.9, 0.99, 0.999, 0.9999]

    for p in probs:
        rounds_m = tests["miller"].get_required_rounds(p)
        res = tests["miller"].is_prime(n, p)
        print(f"  prob={p}: rounds={rounds_m}, result={res}")
        assert res is True


def test_rounds_comparison(tests):
    print("\n[test] rounds comparison (miller should be fastest)")
    p = 0.999
    r_fermat = tests["fermat"].get_required_rounds(p)
    r_solovay = tests["solovay"].get_required_rounds(p)
    r_miller = tests["miller"].get_required_rounds(p)

    print(f"  prob={p}: fermat={r_fermat}, solovay={r_solovay}, miller={r_miller}")

    assert r_miller <= r_solovay
    assert r_miller <= r_fermat
