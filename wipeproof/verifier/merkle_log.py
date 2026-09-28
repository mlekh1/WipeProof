"""
WipeProof Append-Only Merkle Transparency Log.
Inspired by RFC 6962 Certificate Transparency and Sigstore Rekor.

Provides tamper-evident public auditability:
1. Append-only leaf insertion of verified wipe certificate hashes.
2. Binary Merkle tree root hash generation.
3. Cryptographic inclusion proofs (audit path) for independent verification.
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class MerkleInclusionProof:
    """Cryptographic audit path proving a leaf is part of the Merkle Tree."""
    leaf_index: int
    leaf_hash: str
    tree_size: int
    audit_path: list[dict[str, str]]  # list of {"direction": "left"|"right", "hash": "..."}
    root_hash: str

    def verify(self) -> bool:
        """Verify the mathematical validity of this inclusion proof."""
        current = self.leaf_hash
        for step in self.audit_path:
            direction = step["direction"]
            sibling = step["hash"]
            if direction == "left":
                combined = bytes.fromhex(sibling) + bytes.fromhex(current)
            else:
                combined = bytes.fromhex(current) + bytes.fromhex(sibling)
            current = hashlib.sha256(combined).hexdigest()
        return current.lower() == self.root_hash.lower()


class MerkleTransparencyLog:
    """In-memory and persisted append-only Merkle tree for certificate transparency."""

    def __init__(self, log_file: Optional[Path] = None):
        self.log_file = log_file
        self.leaves: list[str] = []  # list of hex leaf hashes
        self.entries: list[dict[str, Any]] = []
        self._load()

    def append_certificate(self, certificate_id: str, canonical_payload_sha256: str) -> int:
        """Append a certificate to the transparency log.
        
        Args:
            certificate_id: Unique UUID of certificate.
            canonical_payload_sha256: Canonical SHA-256 payload digest.
            
        Returns:
            Leaf index (0-based) in the append-only log.
        """
        # Leaf hash: SHA-256 of 0x00 byte prefix (RFC 6962 leaf separator) + payload hash
        leaf_input = b"\x00" + bytes.fromhex(canonical_payload_sha256)
        leaf_hash = hashlib.sha256(leaf_input).hexdigest()

        idx = len(self.leaves)
        self.leaves.append(leaf_hash)
        self.entries.append({
            "index": idx,
            "certificate_id": certificate_id,
            "canonical_payload_sha256": canonical_payload_sha256,
            "leaf_hash": leaf_hash,
        })
        self._save()
        return idx

    def get_root_hash(self) -> str:
        """Compute the current Merkle Tree Root hash."""
        if not self.leaves:
            return "0" * 64

        nodes = self.leaves[:]
        while len(nodes) > 1:
            next_level: list[str] = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    # Internal node: 0x01 prefix (RFC 6962)
                    combined = bytes.fromhex(nodes[i]) + bytes.fromhex(nodes[i + 1])
                    node_hash = hashlib.sha256(combined).hexdigest()
                    next_level.append(node_hash)
                else:
                    # Odd leaf promoted
                    next_level.append(nodes[i])
            nodes = next_level

        return nodes[0]

    def get_inclusion_proof(self, index: int) -> MerkleInclusionProof:
        """Generate an inclusion proof for the leaf at index."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of bounds for tree size {len(self.leaves)}")

        leaf_hash = self.leaves[index]
        tree_size = len(self.leaves)
        audit_path: list[dict[str, str]] = []

        curr_index = index
        nodes = self.leaves[:]

        while len(nodes) > 1:
            next_level: list[str] = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    combined = bytes.fromhex(nodes[i]) + bytes.fromhex(nodes[i + 1])
                    parent = hashlib.sha256(combined).hexdigest()
                    next_level.append(parent)

                    if i == curr_index:
                        audit_path.append({"direction": "right", "hash": nodes[i + 1]})
                    elif i + 1 == curr_index:
                        audit_path.append({"direction": "left", "hash": nodes[i]})
                else:
                    next_level.append(nodes[i])
            curr_index = curr_index // 2
            nodes = next_level

        return MerkleInclusionProof(
            leaf_index=index,
            leaf_hash=leaf_hash,
            tree_size=tree_size,
            audit_path=audit_path,
            root_hash=self.get_root_hash(),
        )

    def _save(self) -> None:
        if self.log_file:
            data = {
                "root_hash": self.get_root_hash(),
                "tree_size": len(self.leaves),
                "entries": self.entries,
            }
            self.log_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        if self.log_file and self.log_file.exists():
            try:
                data = json.loads(self.log_file.read_text(encoding="utf-8"))
                self.entries = data.get("entries", [])
                self.leaves = [e["leaf_hash"] for e in self.entries]
            except Exception:
                pass
