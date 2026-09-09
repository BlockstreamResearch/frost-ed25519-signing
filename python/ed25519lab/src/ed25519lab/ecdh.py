# Copyright (c) 2025- The secp256k1lab Developers
# Copyright (c) 2026- The ed25519lab Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""ECDH key derivation for encrypted share transport (EncPedPop).

The peer key is decoded with GE.from_bytes, which rejects small-order and
mixed-order points. This closes a small-subgroup attack: a torsioned peer key
would make the shared point depend on the decryption key only through
deckey mod 8, leaking three bits per exchange. The security argument rests on
that parse-time check, which is why this function does no cofactor
multiplication of its own.

The raw shared point is never used as key material. It goes into a KDF together
with both public keys, binding the derived key to this pair and session.
"""

from .ed25519 import GE, B, Scalar
from .util import tagged_hash

__all__ = ["TAG_ECDH", "ecdh_ed25519"]

# Verbatim from the spec. Note the space rather than a slash before "ecdh" --
# inherited from the upstream tag name; harmless, but worth normalising if the
# spec is ever revised.
TAG_ECDH = "ChillDKG-ed25519-v1/encpedpop ecdh"


def ecdh_ed25519(seckey: bytes, pubkey: bytes, context: bytes, sending: bool) -> Scalar:
    """Derive the additive encryption pad shared with a peer.

        pad = wide_reduce(tagged_hash(TAG_ECDH, bytes([d]P_peer),
                                      pk_sender, pk_recipient, context))

    `sending` selects the ordering of the two public keys so that both sides
    derive the same pad: the sender puts its own key first, the recipient puts
    the peer's key first. Getting this backwards fails silently, with the two
    sides deriving different pads, so a round-trip test covers it.

    Returns a Scalar because the ciphertext is `share + pad mod L`, which is
    what makes the coordinator's homomorphic summation of ciphertexts work.

    The concatenation is unambiguous: the shared point and both public keys are
    32 bytes each, and `context` is the only variable-length part and comes
    last. See tagged_hash for why that matters.
    """
    d = Scalar.from_bytes_nonzero_checked(seckey)
    # from_bytes refuses the identity as well as small- and
    # mixed-order points, which is exactly this call site's policy.
    peer = GE.from_bytes(pubkey)

    shared = d * peer
    assert not shared.is_identity  # d != 0 and peer has prime order

    own = (d * B).to_bytes()
    pk_sender, pk_recipient = (own, pubkey) if sending else (pubkey, own)

    return Scalar.from_bytes_wide(
        tagged_hash(
            TAG_ECDH,
            shared.to_bytes(),
            pk_sender,
            pk_recipient,
            context,
        )
    )
