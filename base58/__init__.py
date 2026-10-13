'''Base58 encoding

Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
'''

from __future__ import annotations

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.


def _memo(func):
    # Minimal argument-keyed cache; avoids importing functools at load time.
    cache: dict = {}

    def wrapper(*args):
        try:
            return cache[args]
        except KeyError:
            result = cache[args] = func(*args)
            return result
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper

# Prefer the interpreter's builtin SHA-256 module: it yields identical digests
# and avoids loading OpenSSL through hashlib at import time.
try:
    from _sha2 import sha256
except ImportError:
    try:
        from _sha256 import sha256
    except ImportError:
        from hashlib import sha256

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


@_memo
def _get_base58_pair_table(alphabet: bytes) -> list:
    chars = [alphabet[k:k+1] for k in range(len(alphabet))]
    return [a + b for a in chars for b in chars]


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    string = b""
    base = len(alphabet)
    if isinstance(alphabet, bytes) and base > 1 and i > 0:
        pairs = _get_base58_pair_table(alphabet)
        b2 = base * base
        b4 = b2 * b2
        parts = []
        append = parts.append
        while i >= b4:
            i, r = divmod(i, b4)
            append(pairs[r % b2])
            append(pairs[r // b2])
        if i >= b2:
            append(pairs[i % b2])
            i //= b2
        if i >= base:
            append(pairs[i])
        else:
            append(alphabet[i:i+1])
        parts.reverse()
        return b"".join(parts)
    while i:
        i, idx = divmod(i, base)
        string = alphabet[idx:idx+1] + string
    return string


def b58encode(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58
    """
    if isinstance(v, str):
        v = v.encode('ascii')

    origlen = len(v)
    v = v.lstrip(b'\0')
    newlen = len(v)

    acc = int.from_bytes(v, 'big')  # first byte is most significant

    result = b58encode_int(acc, False, alphabet)
    return alphabet[0:1] * (origlen - newlen) + result


@_memo
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


@_memo
def _get_base58_translate_table(alphabet: bytes, autofix: bool) -> bytes:
    invmap = _get_base58_decode_map(alphabet, autofix)
    table = bytearray(b'\xff' * 256)
    for char, index in invmap.items():
        if isinstance(char, int) and 0 <= char < 256:
            table[char] = index
    return bytes(table)


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
    if isinstance(alphabet, bytes) and base < 255 and \
            isinstance(v, bytes):
        table = _get_base58_translate_table(alphabet, autofix)
        digits = v.translate(table)
        if b'\xff' not in digits:
            pad = -len(digits) % 4
            if pad:
                digits = b'\0' * pad + digits
            b2 = base * base
            b3 = b2 * base
            b4 = b3 * base
            decimal = 0
            it = iter(digits)
            for a, b, c, d in zip(it, it, it, it):
                decimal = decimal * b4 + (a * b3 + b * b2 + c * base + d)
            return decimal

    map = _get_base58_decode_map(alphabet, autofix)

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
    if isinstance(v, str):
        v = v.encode('ascii')

    origlen = len(v)
    v = v.lstrip(alphabet[0:1])
    nzeros = origlen - len(v)

    info = None
    if isinstance(v, bytes) and type(alphabet) is bytes:
        cache = _DECODE_INFO_AF if autofix else _DECODE_INFO
        info = cache.get(alphabet)
        if info is None and len(alphabet) < 255:
            base = len(alphabet)
            info = (_get_base58_translate_table(alphabet, bool(autofix)),
                    base, base * base, base ** 3, base ** 4)
            cache[alphabet] = info
    if info is not None:
        table, base, b2, b3, b4 = info
        digits = v.translate(table)
        if b'\xff' not in digits:
            pad = -len(digits) % 4
            if pad:
                digits = b'\0' * pad + digits
            acc = 0
            it = iter(digits)
            for a, b, c, d in zip(it, it, it, it):
                acc = acc * b4 + (a * b3 + b * b2 + c * base + d)
        else:
            acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)
    else:
        acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)

    return acc.to_bytes(nzeros + (acc.bit_length() + 7) // 8, 'big')


_DECODE_INFO: dict = {}
_DECODE_INFO_AF: dict = {}


def b58encode_check(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode a string using Base58 with a 4 character checksum
    """
    if isinstance(v, str):
        v = v.encode('ascii')

    v = v + sha256(sha256(v).digest()).digest()[:4]
    origlen = len(v)
    v = v.lstrip(b'\0')
    result = b58encode_int(int.from_bytes(v, 'big'), False, alphabet)
    return alphabet[0:1] * (origlen - len(v)) + result


def b58decode_check(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    '''Decode and verify the checksum of a Base58 encoded string'''

    v = v.rstrip()
    if isinstance(v, str):
        v = v.encode('ascii')
    origlen = len(v)
    v = v.lstrip(alphabet[0:1])
    nz = origlen - len(v)
    base = len(alphabet)
    acc = -1
    if isinstance(alphabet, bytes) and base < 255:
        digits = v.translate(_get_base58_translate_table(alphabet, autofix))
        if b'\xff' not in digits:
            pad = -len(digits) % 4
            if pad:
                digits = b'\0' * pad + digits
            b2 = base * base
            b3 = b2 * base
            b4 = b3 * base
            acc = 0
            it = iter(digits)
            for a, b, c, d in zip(it, it, it, it):
                acc = acc * b4 + (a * b3 + b * b2 + c * base + d)
    if acc < 0:
        acc = b58decode_int(v, alphabet, autofix=autofix)
    result = acc.to_bytes(nz + (acc.bit_length() + 7) // 8, 'big')
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result
