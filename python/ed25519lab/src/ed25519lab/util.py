# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Hashing and byte helpers.

All integer/byte conversion here is LITTLE-ENDIAN, matching the rest of the
library. Note that this differs from secp256k1lab, where bytes_from_int and
int_from_bytes are big-endian; the names are kept because the role is unchanged.
"""

import hashlib

__all__ = [
    "bytes_from_int",
    "hash_sha512",
    "int_from_bytes",
    "tagged_hash",
    "xor_bytes",
]


def tagged_hash(tag: str, *parts: bytes) -> bytes:
    """Domain-separated hash, 64 bytes out.

        tagged_hash(tag, *parts) == SHA-512(SHA-512(tag)[:32] || parts...)

    The tag is digested rather than prepended so that no tag can be a prefix of
    another.
    """
    return hashlib.sha512(hashlib.sha512(tag.encode()).digest()[:32] + b"".join(parts)).digest()


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="little")


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="little")


def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    assert len(b0) == 32 and len(b1) == 32
    return bytes(x ^ y for (x, y) in zip(b0, b1))


def hash_sha512(b: bytes) -> bytes:
    """Plain SHA-512, untagged.

    Used only for the Ed25519 challenge e = SHA-512(R || A || m), which RFC 8032
    defines without domain separation. All other hashing goes through
    tagged_hash.
    """
    return hashlib.sha512(b).digest()
