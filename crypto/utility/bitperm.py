def bitperm(
    data: bytes,
    p_block: list[int],
    msb_first: bool = True,
    one_based_indexing: bool = True,
) -> bytes:
    total_bits = len(data) * 8
    result_integer = 0

    for i in p_block:
        src_idx = i - 1 if one_based_indexing else i
        if not (0 <= src_idx < total_bits):
            raise IndexError(f"Index {src_idx} is out of range")
        byte_idx = src_idx // 8
        bit_idx_in_byte = src_idx % 8
        src_byte = data[byte_idx]
        if msb_first:
            shift = 7 - bit_idx_in_byte
        else:
            shift = bit_idx_in_byte
        bit_val = (src_byte >> shift) & 1
        result_integer <<= 1
        result_integer |= bit_val

    num_output_bits = len(p_block)
    num_output_bytes = (num_output_bits + 7) // 8

    padding = num_output_bytes * 8 - num_output_bits
    result_integer <<= padding

    return result_integer.to_bytes(num_output_bytes, byteorder="big")


data = b"\x07"  # 00000111
p_block = [1, 7, 6, 5, 4, 3, 2, 1]

result = bitperm(data, p_block, msb_first=True, one_based_indexing=True)