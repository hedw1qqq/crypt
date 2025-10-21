import secrets

from crypto.utility.modes import PaddingMode


def pad(data: bytes, block_size: int, padding: PaddingMode) -> bytes:
    if padding == PaddingMode.ZEROS:
        pad_len = (block_size - (len(data) % block_size)) % block_size
        return data + b"\0" * pad_len
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    if padding == PaddingMode.PKCS7:
        return data + bytes([pad_len]) * pad_len
    if padding == PaddingMode.ANSI_X923:
        return data + b"\0" * (pad_len - 1) + bytes([pad_len])
    if padding == PaddingMode.ISO_10126:
        # рандомные байты + последний - длина
        return data + secrets.token_bytes(pad_len - 1) + bytes([pad_len])
    raise ValueError("Not implemented")


def unpad(data: bytes, block_size: int, padding: PaddingMode) -> bytes:
    if padding == PaddingMode.ZEROS:
        return data.rstrip(b"\0")
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if padding == PaddingMode.PKCS7:
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Invalid PKCS7 padding")
        return data[:-pad_len]
    if padding == PaddingMode.ANSI_X923:
        if any(b != 0 for b in data[-pad_len:-1]):
            raise ValueError("Invalid ANSI X.923 padding")
        return data[:-pad_len]
    if padding == PaddingMode.ISO_10126:
        return data[:-pad_len]
    raise ValueError("Not implemented")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: bytes, block_size: int) -> list:
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def swap(a, b):
    a = a ^ b
    b = a ^ b
    a = a ^ b
    return a, b
