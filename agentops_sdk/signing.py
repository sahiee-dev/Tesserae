"""
agentops_sdk/signing.py — Ed25519 signing primitives.

Every event envelope carries an Ed25519 signature over its event_hash.
The session's public key is embedded in SESSION_START so the verifier
is self-contained — no external key registry needed.

Why Ed25519 over SHA-256 chain alone
--------------------------------------
A hash chain proves internal consistency: if you modify event K you must
recompute all subsequent hashes.  But SHA-256 is a public function — anyone
with file write access and a Python interpreter can recompute the whole
chain cleanly.  Ed25519 signatures require the private key.  Without it,
rewriting a single event produces an invalid signature and the verifier
returns FAIL.

Evidence class upgrade
-----------------------
  NON_AUTHORITATIVE_EVIDENCE         — hash chain only (no signatures)
  SIGNED_NON_AUTHORITATIVE_EVIDENCE  — hash chain + Ed25519  ← this module
  AUTHORITATIVE_EVIDENCE             — server sealed
  SIGNED_AUTHORITATIVE_EVIDENCE      — server sealed + HMAC
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """
    Generate a fresh Ed25519 keypair for a session.

    Returns:
        (private_key, public_key_b64) where public_key_b64 is the
        base64-encoded 32-byte public key, safe to embed in SESSION_START.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode()
    return private_key, public_key_b64


def sign_event_hash(private_key: Ed25519PrivateKey, event_hash_hex: str) -> str:
    """
    Sign the event_hash (64-char hex SHA-256 digest) with the session private key.

    We sign the event_hash rather than re-canonicalising the full payload
    because event_hash is already the canonical commitment to the event.
    If the event is tampered the hash changes and the signature fails.

    Returns:
        base64-encoded 64-byte Ed25519 signature.
    """
    signature_bytes = private_key.sign(event_hash_hex.encode("utf-8"))
    return base64.b64encode(signature_bytes).decode()


def verify_signature(
    public_key_b64: str,
    event_hash_hex: str,
    signature_b64: str,
) -> bool:
    """
    Verify an Ed25519 signature against an event_hash.

    Args:
        public_key_b64:  base64-encoded 32-byte public key (from SESSION_START)
        event_hash_hex:  64-char hex SHA-256 digest (the event's event_hash field)
        signature_b64:   base64-encoded 64-byte signature (from event's signature field)

    Returns:
        True if valid, False for any failure (bad key, bad sig, bad encoding).
    """
    try:
        public_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, event_hash_hex.encode("utf-8"))
        return True
    except (InvalidSignature, Exception):
        return False
