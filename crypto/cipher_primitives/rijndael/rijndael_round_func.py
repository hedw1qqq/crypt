from crypto.cipher_primitives.rijndael.sbox import SBox
from crypto.services.galois_service import GField


def sub_bytes(state: list[bytearray], sbox: SBox, inverse: bool) -> list[bytearray]:
    nb = len(state[0])
    result = [bytearray(nb) for _ in range(4)]

    for i in range(4):
        for j in range(nb):
            val = state[i][j]
            if inverse:
                result[i][j] = sbox.inv_sub(val)
            else:
                result[i][j] = sbox.sub(val)
    return result


def shift_rows(state: list[bytearray], inverse: bool) -> list[bytearray]:
    nb = len(state[0])
    result = [bytearray(nb) for _ in range(4)]

    if nb == 4:
        shifts = [0, 1, 2, 3]
    elif nb == 6:
        shifts = [0, 1, 2, 3]
    else:  # nb == 8
        shifts = [0, 1, 3, 4]

    for r in range(4):
        shift = shifts[r]
        for c in range(nb):
            if inverse:
                source_col = (c + shift) % nb

            else:
                source_col = (c - shift + nb) % nb

            result[r][c] = state[r][source_col]

    return result


def mix_columns(
    state: list[bytearray], mod_poly: int, inverse: bool
) -> list[bytearray]:
    nb = len(state[0])
    result = [bytearray(nb) for _ in range(4)]

    if inverse:
        matrix = [
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E],
        ]
    else:
        matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ]

    for c in range(nb):
        for r in range(4):
            sum_val = 0
            for k in range(4):
                prod = GField.multiply(matrix[r][k], state[k][c], mod_poly)
                sum_val ^= prod
            result[r][c] = sum_val

    return result


def add_round_key(state: list[bytearray], round_key: bytes) -> list[bytearray]:
    nb = len(state[0])
    result = [bytearray(nb) for _ in range(4)]

    for i in range(4):
        for j in range(nb):
            result[i][j] = state[i][j] ^ round_key[j * 4 + i]

    return result
