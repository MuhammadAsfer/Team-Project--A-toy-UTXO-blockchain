"""Pure-Python secp256k1 ECDSA (RFC 6979 deterministic nonce + low-s) and hashing utilities."""
from __future__ import annotations
import hashlib
import hmac

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(hashlib.sha256(data).digest())
    return h.digest()


def point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k: int, point: tuple[int, int] | None = G) -> tuple[int, int] | None:
    if k % N == 0 or point is None:
        return None
    if k < 0:
        return scalar_mult(-k, (point[0], -point[1] % P))
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def privkey_to_pubkey(privkey: int) -> bytes:
    if not (1 <= privkey < N):
        raise ValueError("Private key out of range")
    pt = scalar_mult(privkey, G)
    assert pt is not None
    x, y = pt
    prefix = b"\x02" if (y % 2 == 0) else b"\x03"
    return prefix + x.to_bytes(32, "big")


def parse_pubkey(pubkey: bytes) -> tuple[int, int]:
    if len(pubkey) != 33 or pubkey[0] not in (2, 3):
        raise ValueError("Invalid compressed SEC1 pubkey")
    x = int.from_bytes(pubkey[1:], "big")
    if x >= P:
        raise ValueError("x coordinate >= P")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("Point not on curve")
    if (y % 2) != (pubkey[0] - 2):
        y = P - y
    return (x, y)


def rfc6979_nonce(privkey: int, z_bytes: bytes) -> int:
    x_bytes = privkey.to_bytes(32, "big")
    z_int = int.from_bytes(z_bytes, "big") % N
    z_norm = z_int.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x_bytes + z_norm, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x_bytes + z_norm, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def encode_der(r: int, s: int) -> bytes:
    def int_to_der(val: int) -> bytes:
        b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    rb = int_to_der(r)
    sb = int_to_der(s)
    seq = rb + sb
    return b"\x30" + bytes([len(seq)]) + seq


def decode_der(der: bytes) -> tuple[int, int]:
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("Invalid DER header")
    if der[2] != 0x02:
        raise ValueError("Invalid r marker")
    r_len = der[3]
    if r_len == 0 or 4 + r_len + 2 > len(der):
        raise ValueError("Invalid r length")
    r_bytes = der[4 : 4 + r_len]
    if (r_bytes[0] & 0x80) or (r_len > 1 and r_bytes[0] == 0 and not (r_bytes[1] & 0x80)):
        raise ValueError("Non-canonical r")
    r = int.from_bytes(r_bytes, "big")
    pos = 4 + r_len
    if der[pos] != 0x02:
        raise ValueError("Invalid s marker")
    s_len = der[pos + 1]
    if s_len == 0 or pos + 2 + s_len != len(der):
        raise ValueError("Invalid s length")
    s_bytes = der[pos + 2 :]
    if (s_bytes[0] & 0x80) or (s_len > 1 and s_bytes[0] == 0 and not (s_bytes[1] & 0x80)):
        raise ValueError("Non-canonical s")
    s = int.from_bytes(s_bytes, "big")
    return r, s


def ecdsa_sign(privkey: int, z: bytes) -> bytes:
    if len(z) != 32:
        raise ValueError("z must be 32 bytes")
    z_int = int.from_bytes(z, "big") % N
    k = rfc6979_nonce(privkey, z)
    pt = scalar_mult(k, G)
    assert pt is not None
    r = pt[0] % N
    if r == 0:
        raise ValueError("r == 0")
    s = (pow(k, N - 2, N) * (z_int + r * privkey)) % N
    if s == 0:
        raise ValueError("s == 0")
    if s > N // 2:
        s = N - s
    return encode_der(r, s)


def ecdsa_verify(pubkey: bytes, z: bytes, der_sig: bytes, enforce_low_s: bool = True) -> bool:
    if len(z) != 32:
        return False
    try:
        Q = parse_pubkey(pubkey)
        r, s = decode_der(der_sig)
    except ValueError:
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    if enforce_low_s and s > N // 2:
        return False
    z_int = int.from_bytes(z, "big") % N
    w = pow(s, N - 2, N)
    u1 = (z_int * w) % N
    u2 = (r * w) % N
    pt = point_add(scalar_mult(u1, G), scalar_mult(u2, Q))
    if pt is None:
        return False
    return (pt[0] % N) == r
