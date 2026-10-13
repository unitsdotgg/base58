'''Base58 encoding

Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
'''

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.

from __future__ import annotations

import sys

# hashlib (OpenSSL) and typing are costly to import and are only needed by
# the checksum helpers and by annotations, so they are loaded on demand.
# functools (which pulls in collections) is replaced by a tiny memo, and
# array is only imported by the long-input encode path.


def _memo(f):
    cache = {}

    def wrapper(*args, **kw):
        key = (args, tuple(kw.items())) if kw else args
        try:
            return cache[key]
        except KeyError:
            r = cache[key] = f(*args, **kw)
            return r
    # Hot callers read wrapper.cache directly with a positional-args key.
    wrapper.cache = cache
    wrapper.__wrapped__ = f
    wrapper.__name__ = f.__name__
    wrapper.__doc__ = f.__doc__
    return wrapper

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
    if i.bit_length() > 512:
        vec = _get_encode_vec(alphabet)
        if vec is not None:
            from array import array
            # Collect base**4 remainders, then split all of them at once:
            # 64-bit lanes hold r < 2**24; floor division by sq and base is
            # done per lane with exact multiply-shift reciprocals.
            m1, m2, tbl, big5, m5 = vec
            if big5:
                # base**5 < 2**30 is still a single-limb divisor: 20% fewer
                # whole-number division passes. 64-bit lanes hold r < 2**30.
                while i:
                    i, r = divmod(i, big5)
                    append(r)
                n = len(parts)
                arr = array('Q', parts)
                if _BIG_ENDIAN_HOST:
                    arr.byteswap()
                x = int.from_bytes(arr.tobytes(), 'little')
                # Lane masks are cached at a capacity >= n: every masked
                # value is already < 2**(64*n), so a longer mask is
                # harmless; only the OR constant is cut to 64*n bits.
                c = _vec_masks
                if n > c[0]:
                    _grow_vec_masks(n)
                k18 = c[1]
                q1 = ((x * m5) >> 42) & k18
                lo = x - q1 * sq
                q2 = ((q1 * m5) >> 42) & k18
                p = lo | ((q1 - q2 * sq) << 32)
                q = ((p * m2) >> 20) & c[2]
                f = (p - q * base) | (q << 8) | (q2 << 48) | (
                    c[3] & ((1 << (n << 6)) - 1))
                return f.to_bytes(8 * n, 'big').translate(
                    tbl, b'\xff').lstrip(alphabet[0:1])
            while i:
                i, r = divmod(i, big)
                append(r)
            n = len(parts)
            arr = array('Q', parts)
            if _BIG_ENDIAN_HOST:
                arr.byteswap()
            x = int.from_bytes(arr.tobytes(), 'little')
            h = ((x * m1) >> 40) & int.from_bytes(
                b'\xff\x0f\0\0\0\0\0\0' * n, 'little')
            v = (x - h * sq) | (h << 32)
            q = ((v * m2) >> 20) & int.from_bytes(
                b'\xff\0\0\0' * (2 * n), 'little')
            f = (q << 8) | (v - q * base) | int.from_bytes(
                b'\0\0\xff\xff' * (2 * n), 'little')
            return f.to_bytes(8 * n, 'big').translate(
                tbl, b'\xff').lstrip(alphabet[0:1])
    while i:
        i, r = divmod(i, big)
        hi, lo = divmod(r, sq)
        append(pairs[lo])
        append(pairs[hi])
    parts.reverse()
    return b''.join(parts).lstrip(alphabet[0:1])


@_memo
def _get_encode_table(alphabet: bytes):
    chars = [alphabet[j:j+1] for j in range(len(alphabet))]
    pairs = [a + b for a in chars for b in chars]
    sq = len(alphabet) ** 2
    if alphabet[0] in alphabet[1:]:
        pairs = None
    return pairs, sq, sq * sq


_BIG_ENDIAN_HOST = sys.byteorder != 'little'

# [capacity in 64-bit lanes, k18 mask, low-byte mask, OR constant]
_vec_masks = [0, 0, 0, 0]


def _grow_vec_masks(n: int) -> None:
    m = max(n, 2 * _vec_masks[0], 64)
    frm = int.from_bytes
    _vec_masks[:] = [
        m,
        frm(b'\xff\xff\x03\0\0\0\0\0' * m, 'little'),
        frm(b'\xff\0\0\0' * (2 * m), 'little'),
        frm(b'\0\0\xff\xff\0\0\0\xff' * m, 'little'),
    ]


@_memo
def _get_encode_vec(alphabet: bytes):
    # Lane bounds need base <= 64: r < base**4 <= 2**24, base**2 <= 4096.
    # With M = ceil(2**s / d) and e = M*d - 2**s < d, floor(r*M >> s) is
    # floor(r / d) whenever r*e < 2**s, which holds for s=40 (stage 1,
    # r < 2**24, d <= 4096) and s=20 (stage 2, v < 4096, d <= 64).
    base = len(alphabet)
    if base > 64 or not isinstance(alphabet, bytes):
        return None
    sq = base * base
    m1 = -(-(1 << 40) // sq)
    m2 = -(-(1 << 20) // base)
    # 5-digit lanes (41 <= base, base**5 < 2**30): stage s=42 splits r by
    # base**2 exactly (r < 2**30, e < 2**12) and r*m5 < 2**62 stays in-lane.
    big5 = m5 = 0
    if base >= 41 and base ** 5 < (1 << 30):
        big5 = base ** 5
        m5 = -(-(1 << 42) // sq)
    return m1, m2, alphabet + bytes(256 - base), big5, m5


@_memo
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
    key = (1 << (n - 1).bit_length(), base)
    sub, plan, s, tail = _plan_cache.get(key) or _merge_plan(*key)
    for shift, mask, c in sub:
        x -= ((x >> shift) & mask) * c
    for shift, hmask, mult, mask in plan:
        x = ((x >> shift) & hmask) * mult + (x & mask)
    if not tail:
        return x
    # Finish with dense pairwise merges of the few remaining lanes, so the
    # large multiplications do not carry the zero gaps between lanes.
    m = (1 << s) - 1
    lanes = [(x >> k) & m for k in range(s * ((1 << len(tail)) - 1), 0, -s)]
    lanes.append(x & m)
    for mult in tail:
        it = iter(lanes)
        lanes = [a * mult + b for a, b in zip(it, it)]
    return lanes[0]


@_memo
def _merge_plan(n2: int, base: int):
    plan = []
    w = 1
    mult = base
    # Number of lanes finished by dense pairwise merges.
    lanes = 16 if n2 >= 2048 else 8 if n2 >= 512 else 1
    stop = n2 // lanes
    # base = odd * 2**t: the 2**(t*w) factor of base**w is folded into a
    # shorter shift and a pre-shifted mask, so each round multiplies by the
    # smaller odd**w ((x >> s & m) << k == x >> (s - k) & (m << k), k < s).
    t = (base & -base).bit_length() - 1
    odd = base >> t
    # While 256**w - base**w is a single limb, merge in subtraction form:
    # x -= hi * (256**w - base**w) turns hi*256**w + lo into hi*base**w + lo.
    sub = []
    while w < stop and (1 << 8 * w) - mult < (1 << 30):
        mask = int.from_bytes(
            (b'\0' * w + b'\xff' * w) * (n2 // (2 * w)), 'big')
        sub.append((8 * w, mask, (1 << 8 * w) - mult))
        odd *= odd
        mult *= mult
        w <<= 1
    while w < stop:
        mask = int.from_bytes(
            (b'\0' * w + b'\xff' * w) * (n2 // (2 * w)), 'big')
        plan.append((8 * w - t * w, mask << (t * w), odd, mask))
        odd *= odd
        mult *= mult
        w <<= 1
    tail = []
    while w < n2:
        tail.append(mult)
        mult *= mult
        w <<= 1
    return tuple(sub), tuple(plan), 8 * stop, tuple(tail)


_plan_cache = _merge_plan.cache
_table_cache = _get_decode_table.cache


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

    acc = int.from_bytes(v, byteorder='big')  # first byte is most significant

    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
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


def b58decode_int(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    if b' ' not in alphabet:
        v = v.rstrip()
    if isinstance(v, str):
        v = v.encode('ascii')

    base = len(alphabet)
    if 2 <= base <= 255 and isinstance(v, (bytes, bytearray)):
        digits = v.translate(_table_cache.get((alphabet, autofix)) or
                             _get_decode_table(alphabet, autofix))
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
    if isinstance(v, str):
        v = v.encode('ascii')

    origlen = len(v)
    v = v.lstrip(alphabet[0:1])
    newlen = len(v)

    base = len(alphabet)
    if 2 <= base <= 255 and isinstance(v, (bytes, bytearray)):
        digits = v.translate(_table_cache.get((alphabet, autofix)) or
                             _get_decode_table(alphabet, autofix))
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
    from hashlib import sha256
    v = scrub_input(v)

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4], alphabet=alphabet)


def b58decode_check(
    v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET, *,
    autofix: bool = False
) -> bytes:
    '''Decode and verify the checksum of a Base58 encoded string'''
    from hashlib import sha256

    result = b58decode(v, alphabet=alphabet, autofix=autofix)
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result
