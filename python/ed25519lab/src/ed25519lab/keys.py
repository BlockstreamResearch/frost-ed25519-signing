# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from .ed25519 import B, Scalar

__all__ = ["pubkey_gen"]


def pubkey_gen(seckey: bytes) -> bytes:
    """Return the public key corresponding to a raw-scalar secret key.

    `seckey` is a scalar in 1..L-1, little-endian. It is not an RFC 8032 seed:
    there is no clamping, no SHA-512 expansion and no nonce prefix. Raises
    ValueError if the value is zero or >= L, which is the case for about 15 out
    of 16 uniform 32-byte strings.
    """
    d = Scalar.from_bytes_nonzero_checked(seckey)
    p = d * B
    assert not p.is_identity
    return p.to_bytes()
