# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Verification of aggregate FROST signatures.

The aggregate signature is an ordinary Ed25519 signature and must verify under
any RFC 8032 verifier, including Solana's.

Not to be confused with internal_sig.internal_verify, which checks the
domain-separated scheme used for proofs of possession and CertEq. That scheme
is not Ed25519, and its signatures do not verify here.
"""

from .ed25519 import GE, B, Scalar
from .util import hash_sha512

__all__ = ["ed25519_verify"]


def ed25519_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Verify a standard Ed25519 signature, cofactorless: [s]B == R + [e]A.

    Rejects, in order: wrong signature length; a non-canonical or off-curve or
    out-of-subgroup A or R; s >= L; the neutral element as A or R; and finally a
    failing group equation.

    Stricter than dalek verify_strict, which rejects only small-order A and R
    and accepts mixed-order ones. This answers "valid under this library's
    rules", not "would Solana accept this".
    """
    if len(sig) != 64:
        return False
    try:
        a = GE.from_bytes(pubkey)
        r = GE.from_bytes(sig[0:32])
        s = Scalar.from_bytes_checked(sig[32:64])
    except ValueError:
        return False

    e = Scalar.from_bytes_wide(hash_sha512(sig[0:32] + pubkey + msg))
    return s * B == r + e * a
