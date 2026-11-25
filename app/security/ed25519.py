"""纯标准库的 Ed25519（RFC 8032）实现。

只依赖 hashlib 的 SHA-512，运行环境无需任何第三方加密包。
外部复核方离线核验时只需要本模块的 ``verify`` 与公钥字节，
不接触工作台、数据库或任何在线服务。
"""
import hashlib
import os

# 曲线参数：-1 mod 2^255，素数 p = 2^255 - 19
p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)


def _xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


_By = 4 * pow(5, p - 2, p)
_Bx = _xrecover(_By)
B = (_Bx % p, _By % p)


def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    dxy = d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxy, p - 2, p)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - dxy, p - 2, p)
    return x3 % p, y3 % p


def _scalarmult(P, e):
    if e == 0:
        return 0, 1
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _encodeint(y):
    return y.to_bytes(32, "little")


def _encodepoint(P):
    x, y = P
    bits = y & ((1 << 255) - 1)
    bits |= (x & 1) << 255
    return bits.to_bytes(32, "little")


def _inv(x):
    return pow(x, p - 2, p)


def _decodepoint(s):
    if len(s) != 32:
        raise ValueError("BAD_POINT")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    x = _xrecover(y)
    if (x & 1) != sign:
        x = p - x
    P = (x, y)
    if _encodepoint(P) != s:
        raise ValueError("BAD_POINT")
    return P


def _clamped_scalar(h):
    # RFC 8032：清零最低 3 位与最高位 bit255，并强制 bit254 为 1
    total = int.from_bytes(h[:32], "little")
    total &= (1 << 254) - 8
    total |= 1 << 254
    return total


def public_from_secret(secret32: bytes) -> bytes:
    if len(secret32) != 32:
        raise ValueError("BAD_SECRET_KEY")
    h = hashlib.sha512(secret32).digest()
    a = _clamped_scalar(h)
    return _encodepoint(_scalarmult(B, a))


def generate_keypair() -> tuple[bytes, bytes]:
    """返回 (seed32 私钥, 32 字节公钥)。签名只需要 seed。"""
    seed = os.urandom(32)
    return seed, public_from_secret(seed)


def sign(secret32: bytes, message: bytes) -> bytes:
    if len(secret32) != 32:
        raise ValueError("BAD_SECRET_KEY")
    h = hashlib.sha512(secret32).digest()
    a = _clamped_scalar(h)
    A = _encodepoint(_scalarmult(B, a))
    r = _hint(h[32:] + message) % L
    R = _encodepoint(_scalarmult(B, r))
    k = _hint(R + A + message) % L
    S = (r + k * a) % L
    return R + S.to_bytes(32, "little")


def verify(public32: bytes, message: bytes, signature64: bytes) -> bool:
    """严格核验；任何异常都归为验签失败，绝不抛给调用方。"""
    try:
        if len(public32) != 32 or len(signature64) != 64:
            return False
        R = _decodepoint(signature64[:32])
        A = _decodepoint(public32)
        S = int.from_bytes(signature64[32:], "little")
        if S >= L:
            return False
        k = _hint(signature64[:32] + public32 + message) % L
        return _scalarmult(B, S) == _edwards_add(R, _scalarmult(A, k))
    except (ValueError, OverflowError):
        return False
