# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""The internal signature scheme used for proofs of possession and CertEq.

Not Ed25519, and not verifiable as Ed25519. The domain tag enters the challenge
before R and the public key:

    e = wide_reduce(tagged_hash(TAG_CHALLENGE, bytes(R), bytes(A), m))

Standard Ed25519 computes e = wide_reduce(SHA-512(bytes(R) || bytes(A) || m)).
Since R and A are fixed by the signature and the key, no message makes the two
challenges agree, so a PoP or CertEq signature cannot be replayed as an ordinary
signature of the host key. Tagging the message instead would yield a valid
Ed25519 signature over tag || m, which is the outcome to avoid.

The nonce is keyed by the raw secret scalar, since raw-scalar host keys have no
seed to derive a prefix from:

    k = wide_reduce(tagged_hash(TAG_NONCE, d_le, aux, m))

Deterministic nonces are safe because these are single-party signatures; the
multi-party derandomization attack does not apply. `aux` is optional extra
entropy and must be exactly 32 bytes.
"""

from .ed25519 import GE, B, Scalar
from .util import tagged_hash

__all__ = ["TAG_CHALLENGE", "TAG_NONCE", "internal_sign", "internal_verify"]

TAG_NONCE = "ChillDKG-ed25519-v1/int/nonce"
TAG_CHALLENGE = "ChillDKG-ed25519-v1/int/challenge"

# aux is fixed-width on purpose; see the note in internal_sign.
AUX_SIZE = 32
NO_AUX = b"\x00" * AUX_SIZE


def internal_sign(msg: bytes, seckey: bytes, aux: bytes = NO_AUX) -> bytes:
    """Sign msg with a raw secret scalar. Returns 64 bytes, bytes(R) || le(s).

    `aux` must be exactly 32 bytes; pass NO_AUX for the deterministic variant.
    The width is fixed because the nonce input is d_le || aux || m. Were aux
    variable-length, distinct (aux, m) pairs could collide and produce one k for
    two different messages, which leaks the key: same R, different challenges,
    d = (s1 - s2) / (e1 - e2).
    """
    if len(aux) != AUX_SIZE:
        raise ValueError(f"aux must be exactly {AUX_SIZE} bytes, got {len(aux)}")
    d = Scalar.from_bytes_nonzero_checked(seckey)
    a = d * B
    assert not a.is_identity

    k = Scalar.from_bytes_wide(tagged_hash(TAG_NONCE, d.to_bytes(), aux, msg))
    if k == 0:
        raise RuntimeError("Failure. This happens only with negligible probability.")
    r = k * B
    assert not r.is_identity

    e = Scalar.from_bytes_wide(
        tagged_hash(TAG_CHALLENGE, r.to_bytes(), a.to_bytes(), msg)
    )
    s = k + e * d
    sig = r.to_bytes() + s.to_bytes()
    assert internal_verify(msg, a.to_bytes(), sig)
    return sig


def internal_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Verify an internal signature. Returns False rather than raising.

    The group equation is cofactorless: [s]B == R + [e]A

    The cofactorless one is written to keep a single equation across the 
    protocol and to match what Solana enforces for the final aggregate signature.

    A is [d]B and R is [k]B with d and k nonzero, so neither can legitimately be
    the identity; from_bytes rejects it during decoding, and no separate check
    is needed here.
    """
    if len(pubkey) != 32:
        raise ValueError("The public key must be a 32-byte array.")
    if len(sig) != 64:
        raise ValueError("The signature must be a 64-byte array.")
    try:
        a = GE.from_bytes(pubkey)
        r = GE.from_bytes(sig[0:32])
        s = Scalar.from_bytes_checked(sig[32:64])
    except ValueError:
        return False

    e = Scalar.from_bytes_wide(tagged_hash(TAG_CHALLENGE, sig[0:32], pubkey, msg))
    return s * B == r + e * a
