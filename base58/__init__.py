'''Base58 encoding

Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
'''

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.

from functools import lru_cache
from hashlib import sha256
from typing import Mapping, Union

__version__ = '2.1.1'

# 58 character alphabet used
BITCOIN_ALPHABET = \
    b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
RIPPLE_ALPHABET = b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'
XRP_ALPHABET = RIPPLE_ALPHABET

# Retro compatibility
alphabet = BITCOIN_ALPHABET


def scrub_input(v: Union[str, bytes]) -> bytes:
    if isinstance(v, str):
        v = v.encode('ascii')

    return v


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    base = len(alphabet)
    if i < 0 or base > 256 or base < 2:
        string = b""
        while i:
            i, idx = divmod(i, base)
            string = alphabet[idx:idx+1] + string
        return string
    pairs, sq, big = _get_encode_table(alphabet)
    if pairs is None:
        string = b""
        while i:
            i, idx = divmod(i, base)
            string = alphabet[idx:idx+1] + string
        return string
    parts = []
    append = parts.append
    if i.bit_length() > 16384:
        cube = sq * base
        big5 = big * base
        if big5 < 1 << 30:
            chars = _get_char_table(alphabet)
            while i:
                i, r = divmod(i, big5)
                hi, r = divmod(r, cube)
                mid, lo = divmod(r, base)
                append(chars[lo])
                append(pairs[mid])
                append(pairs[hi])
            parts.reverse()
            return b''.join(parts).lstrip(alphabet[0:1])
    while i:
        i, r = divmod(i, big)
        hi, lo = divmod(r, sq)
        append(pairs[lo])
        append(pairs[hi])
    parts.reverse()
    return b''.join(parts).lstrip(alphabet[0:1])


@lru_cache()
def _get_encode_table(alphabet: bytes):
    chars = [alphabet[j:j+1] for j in range(len(alphabet))]
    pairs = [a + b for a in chars for b in chars]
    sq = len(alphabet) ** 2
    if alphabet[0] in alphabet[1:]:
        pairs = None
    return pairs, sq, sq * sq


@lru_cache()
def _get_char_table(alphabet: bytes):
    return [alphabet[j:j+1] for j in range(len(alphabet))]


@lru_cache()
def _get_decode_table(alphabet: bytes, autofix: bool):
    invmap = _get_base58_decode_map(alphabet, autofix=autofix)
    tbl = bytearray(b'\xff' * 256)
    for char, idx in invmap.items():
        tbl[char] = idx
    return bytes(tbl)


def _digits_to_int(d: bytes, base: int) -> int:
    n = len(d)
    if n <= 12:
        acc = 0
        for c in d:
            acc = acc * base + c
        return acc
    x = int.from_bytes(d, 'big')
    for shift, mask, mult in _merge_plan(1 << (n - 1).bit_length(), base):
        x = ((x >> shift) & mask) * mult + (x & mask)
    return x


@lru_cache(maxsize=4096)
def _merge_plan(n2: int, base: int):
    plan = []
    w = 1
    mult = base
    while w < n2:
        mask = int.from_bytes(
            (b'\0' * w + b'\xff' * w) * (n2 // (2 * w)), 'big')
        plan.append((8 * w, mask, mult))
        mult *= mult
        w <<= 1
    return tuple(plan)


def b58encode(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58
    """
    v = scrub_input(v)

    origlen = len(v)
    v = v.lstrip(b'\0')
    newlen = len(v)

    acc = int.from_bytes(v, byteorder='big')  # first byte is most significant

    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
    return alphabet[0:1] * (origlen - newlen) + result


@lru_cache()
def _get_base58_decode_map(alphabet: bytes,
                           autofix: bool) -> Mapping[int, int]:
    invmap = {char: index for index, char in enumerate(alphabet)}

    if autofix:
        groups = [b'0Oo', b'Il1']
        for group in groups:
            pivots = [c for c in group if c in invmap]
            if len(pivots) == 1:
                for alternative in group:
                    invmap[alternative] = invmap[pivots[0]]

    return invmap


def b58decode_int(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    if b' ' not in alphabet:
        v = v.rstrip()
    v = scrub_input(v)

    base = len(alphabet)
    if 2 <= base <= 255 and isinstance(v, (bytes, bytearray)):
        digits = v.translate(_get_decode_table(alphabet, autofix))
        bad = digits.find(255)
        if bad >= 0:
            raise ValueError(
                "Invalid character {!r}".format(chr(v[bad]))
            )
        return _digits_to_int(digits, base)

    map = _get_base58_decode_map(alphabet, autofix=autofix)

    decimal = 0
    try:
        for char in v:
            decimal = decimal * base + map[char]
    except KeyError as e:
        raise ValueError(
            "Invalid character {!r}".format(chr(e.args[0]))
        ) from None
    return decimal


def b58decode(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    """
    Decode a Base58 encoded string
    """
    v = v.rstrip()
    v = scrub_input(v)

    origlen = len(v)
    v = v.lstrip(alphabet[0:1])
    newlen = len(v)

    base = len(alphabet)
    if 2 <= base <= 255 and isinstance(v, (bytes, bytearray)):
        digits = v.translate(_get_decode_table(alphabet, autofix))
        bad = digits.find(255)
        if bad >= 0:
            raise ValueError(
                "Invalid character {!r}".format(chr(v[bad]))
            )
        acc = _digits_to_int(digits, base)
    else:
        acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)

    return acc.to_bytes(origlen - newlen + (acc.bit_length() + 7) // 8, 'big')


def b58encode_check(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58 with a 4 character checksum
    """
    v = scrub_input(v)

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4], alphabet=alphabet)


def b58decode_check(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    '''Decode and verify the checksum of a Base58 encoded string'''

    result = b58decode(v, alphabet=alphabet, autofix=autofix)
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result
