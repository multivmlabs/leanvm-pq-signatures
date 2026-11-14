"""SHAKE host references and constrained custom-leanISA sponge source.

The VM opcode is the complete Keccak-f[1600] permutation.  Its usual DSL
convenience functions add Ethereum padding; these functions explicitly build
the SHAKE state instead, including its 0x1f domain byte and final 0x80 bit.
Inputs and outputs are byte HeapBufs, addressed by GEN**byte_index.  The only
advice used is the VM's checked implicit bit decomposition.
"""
from __future__ import annotations

import hashlib


def digest(data: bytes, length: int, bits: int = 256) -> bytes:
    if bits not in (128, 256) or length < 0:
        raise ValueError("SHAKE requires bits=128/256 and a nonnegative output length")
    return (hashlib.shake_128 if bits == 128 else hashlib.shake_256)(data).digest(length)


def dsl_helpers() -> str:
    """Reusable checked bytes, word unpacking, and an unpadded permutation."""
    return '''
def shake_checked_byte(value):
    bits = StackBuf(8)
    hint_decompose_bits(bits, value, 8)
    raw = 0
    for j in unroll(0, 8):
        b = bits[j]
        bits[j] = b * b
        raw = raw + b * const(2 ** j)
    assert raw == value
    return value


def shake_unpack_word(word, out, at):
    bits = StackBuf(128)
    hint_decompose_bits(bits, word, 128)
    raw = 0
    for j in unroll(0, 128):
        b = bits[j]
        bits[j] = b * b
        raw = raw + b * const(2 ** j)
    assert raw == word
    for byte in unroll(0, 16):
        value = 0
        for bit in unroll(0, 8):
            value = value + bits[byte * 8 + bit] * const(2 ** bit)
        out[at * GEN ** byte] = value
    return


def shake_permute(state: StackBuf(13)):
    out = StackBuf(13)
    keccak(state[0:2], state[2:4], out, tail=state[4:8], cap=state)
    return out

'''


def dsl_function(name: str, input_bytes: int, output_bytes: int, bits: int = 256) -> str:
    """Emit name(data)->byte HeapBuf for compile-time lengths.

    All input bytes are checked, even when the caller already checked them.
    Returned storage is rounded up to sixteen bytes, but only output_bytes
    bytes belong to the XOF output; extra bytes must not be consumed.
    """
    if not name.isidentifier() or input_bytes < 0 or output_bytes < 1 or bits not in (128, 256):
        raise ValueError("invalid SHAKE function parameters")
    rate = 168 if bits == 128 else 136
    blocks = input_bytes // rate + 1
    output_storage = ((output_bytes + 15) // 16) * 16
    lines = [f"def {name}(data):", f"    checked = HeapBuf({max(input_bytes, 1)})"]
    if input_bytes:
        lines += [f"    for i in mul_range(1, GEN ** {input_bytes}):",
                  "        checked[i] = shake_checked_byte(data[i])"]
    lines += ["    state = StackBuf(13)", "    for j in unroll(0, 13):", "        state[j] = 0"]
    for block in range(blocks):
        padded = {}
        for byte in range(rate):
            offset = block * rate + byte
            if offset < input_bytes:
                padded[byte] = f"checked[GEN ** {offset}]"
        if block == blocks - 1:
            pad = input_bytes % rate
            padded[pad] = str(0x1f | (0x80 if pad == rate - 1 else 0))
            if pad != rate - 1:
                padded[rate - 1] = "128"
        lines += [f"    absorb_{block} = StackBuf(13)"]
        # State cell 8 holds lane 16 only. Cells 9..12 resume with lane
        # 17, so bytes after byte 135 need an eight-byte layout shift.
        def state_position(byte):
            shifted = byte + (8 if byte >= 136 else 0)
            return shifted // 16, shifted % 16

        for word in range(13):
            terms = [f"{value} * const(2 ** {8 * state_position(byte)[1]})"
                     for byte, value in padded.items() if state_position(byte)[0] == word]
            value = f"state[{word}]" + (" + " + " + ".join(terms) if terms else "")
            lines.append(f"    absorb_{block}[{word}] = {value}")
        lines.append(f"    state = shake_permute(absorb_{block})")
    lines.append(f"    result = HeapBuf({output_storage + 16})")
    offset = 0
    squeeze = 0
    while offset < output_bytes:
        take = min(rate, output_bytes - offset)
        # SHAKE rates end halfway through a packed cell.  Unpack into scratch
        # before copying only rate bytes, so capacity bytes never leak into XOF.
        last_word = (take - 1 + (8 if take > 136 else 0)) // 16
        lines.append(f"    chunk_{squeeze} = HeapBuf({(last_word + 1) * 16})")
        for word in range(last_word + 1):
            lines.append(f"    shake_unpack_word(state[{word}], chunk_{squeeze}, GEN ** {word * 16})")
            byte_start = word * 16 - (8 if word >= 9 else 0)
            byte_count = min(8 if word == 8 else 16, take - byte_start)
            lines += [f"    for i in mul_range(1, GEN ** {byte_count}):",
                      f"        result[i * GEN ** {offset + byte_start}] = chunk_{squeeze}[i * GEN ** {word * 16}]"]
        offset += take
        squeeze += 1
        if offset < output_bytes:
            lines.append("    state = shake_permute(state)")
    lines += ["    return result", "", ""]
    return "\n".join(lines)
