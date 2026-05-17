"""
agentops_sdk/merkle.py — RFC 6962 Merkle tree for session audit logs.

Follows Certificate Transparency (RFC 6962 §2.1) exactly:

  Leaf hash:     SHA-256(0x00 || raw_event_hash_bytes)
  Internal hash: SHA-256(0x01 || left_digest || right_digest)
  k-split:       k = largest power of 2 strictly less than n

The 0x00/0x01 domain separation prevents second-preimage attacks where
an adversary constructs a valid "leaf" by concatenating two internal
node digests.

Why Merkle on top of the hash chain
-------------------------------------
The hash chain guarantees order and completeness but requires O(n) work
to verify any single event.  The Merkle tree gives:

  1. O(log n) inclusion proofs — prove event K is in this session
     by supplying only log₂(n) sibling hashes.
  2. A compact 32-byte session commitment (root hash) that can be
     published externally (GitHub commit, transparency log, tweet)
     independent of the full JSONL file.
  3. The root is sealed inside SESSION_END whose payload is covered
     by the Ed25519 signature — so tampering with the root breaks both
     the hash chain AND the signature.

Reference: https://www.rfc-editor.org/rfc/rfc6962#section-2.1
"""
from __future__ import annotations

import hashlib

# RFC 6962 §2.1 domain separation prefixes
_LEAF_PREFIX     = b'\x00'
_INTERNAL_PREFIX = b'\x01'


# ── Core hash primitives ──────────────────────────────────────────────────────

def _leaf_hash(event_hash_hex: str) -> bytes:
    """SHA-256(0x00 || raw_32_bytes_of_event_hash)."""
    return hashlib.sha256(_LEAF_PREFIX + bytes.fromhex(event_hash_hex)).digest()


def _internal_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left_digest || right_digest)."""
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


def _k_split(n: int) -> int:
    """
    Largest power of 2 strictly less than n (RFC 6962 k-split value).
    Guarantees k < n ≤ 2k, producing an imbalanced but well-defined tree.
    """
    return 1 << ((n - 1).bit_length() - 1)


# ── Recursive tree computation (RFC 6962 MTH) ────────────────────────────────

def _mth(leaves: list[bytes]) -> bytes:
    """
    RFC 6962 Merkle Tree Hash over a list of pre-hashed leaf digests.
    MTH({})      = SHA-256(b'')
    MTH({d(0)}) = leaves[0]          (already leaf-hashed)
    MTH(D[n])   = internal_hash(MTH(D[0:k]), MTH(D[k:n]))
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _k_split(n)
    return _internal_hash(_mth(leaves[:k]), _mth(leaves[k:]))


# ── Public API ────────────────────────────────────────────────────────────────

def compute_merkle_root(event_hashes: list[str]) -> str:
    """
    Compute Merkle root over a list of event_hash hex strings.

    Args:
        event_hashes: ordered list of 64-char SHA-256 hex digests

    Returns:
        64-char hex root hash
    """
    if not event_hashes:
        return hashlib.sha256(b"").hexdigest()
    leaves = [_leaf_hash(h) for h in event_hashes]
    return _mth(leaves).hex()


def compute_inclusion_proof(event_hashes: list[str], index: int) -> list[str]:
    """
    Compute RFC 6962 audit path (inclusion proof) for the leaf at `index`.

    The proof is a list of sibling node hashes from leaf to root.
    Verifying: recompute root from leaf + proof and compare against known root.

    Args:
        event_hashes: full ordered list of event_hash hex strings
        index:        0-based position of the leaf to prove

    Returns:
        list of 64-char hex sibling hashes (O(log n) length)
    """
    leaves = [_leaf_hash(h) for h in event_hashes]
    path: list[bytes] = []
    _audit_path(leaves, index, path)
    return [h.hex() for h in path]


def verify_inclusion_proof(
    root_hex: str,
    leaf_event_hash: str,
    leaf_index: int,
    total_leaves: int,
    proof_hashes: list[str],
) -> bool:
    """
    Verify an RFC 6962 inclusion proof against a known Merkle root.

    Args:
        root_hex:        64-char hex root hash (from SESSION_END payload)
        leaf_event_hash: event_hash of the event being proved
        leaf_index:      0-based position of that event in the session
        total_leaves:    total number of events covered by the tree
        proof_hashes:    sibling hashes from compute_inclusion_proof()

    Returns:
        True if the leaf is provably in the tree with this root.
    """
    try:
        # The path from compute_inclusion_proof is in inner-to-outer order
        # (leaf-first, root-last).  The left/right decision at each level must
        # be derived by simulating the descent outer-to-inner, then reversed.
        decisions: list[bool] = []   # True = current is LEFT at that level
        m, n = leaf_index, total_leaves
        for _ in range(len(proof_hashes)):
            k = _k_split(n)
            if m < k:
                decisions.append(True)   # leaf is in left subtree, sibling is right
                n = k
            else:
                decisions.append(False)  # leaf is in right subtree, sibling is left
                m -= k
                n -= k
        decisions.reverse()  # align with inner-to-outer path order

        current = _leaf_hash(leaf_event_hash)
        for sibling_hex, is_left in zip(proof_hashes, decisions):
            sibling = bytes.fromhex(sibling_hex)
            if is_left:
                current = _internal_hash(current, sibling)
            else:
                current = _internal_hash(sibling, current)

        return current.hex() == root_hex
    except Exception:
        return False


# ── Internal: RFC 6962 PATH(m, D[n]) ─────────────────────────────────────────

def _audit_path(leaves: list[bytes], m: int, path: list[bytes]) -> None:
    """
    Recursive RFC 6962 audit path construction.
    PATH(0, {d(0)}) = []
    PATH(m, D[n])   = PATH(m, D[0:k]) + [MTH(D[k:n])]   if m < k
    PATH(m, D[n])   = PATH(m-k, D[k:n]) + [MTH(D[0:k])] if m >= k
    """
    n = len(leaves)
    if n == 1:
        return
    k = _k_split(n)
    if m < k:
        _audit_path(leaves[:k], m, path)
        path.append(_mth(leaves[k:]))
    else:
        _audit_path(leaves[k:], m - k, path)
        path.append(_mth(leaves[:k]))
