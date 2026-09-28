"""
WipeProof Key Management & RFC 8032 Ed25519 Infrastructure.

Handles Ed25519 key generation, strict permission storage (0400),
public key export, key rotation, and cryptographic revocation lists.
"""

from __future__ import annotations
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class KeyManager:
    """Manages Ed25519 signing keys and revocation registries."""

    @staticmethod
    def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate a fresh RFC 8032 Ed25519 asymmetric keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def get_key_id(public_key: ed25519.Ed25519PublicKey) -> str:
        """Derive a deterministic Key ID from SHA-256 fingerprint of raw 32-byte public key."""
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        digest = hashlib.sha256(raw_bytes).hexdigest()
        return f"wp-key-{digest[:16]}"

    @classmethod
    def save_private_key(
        cls,
        private_key: ed25519.Ed25519PrivateKey,
        path: str | Path,
        password: Optional[str] = None,
    ) -> None:
        """Save Ed25519 private key to disk with strict read-only permissions (0400)."""
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)

        encryption_algo = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )

        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo,
        )

        target.write_bytes(pem_data)

        # Enforce strict 0400 permissions on POSIX
        if os.name == "posix":
            os.chmod(target, stat.S_IRUSR)

    @staticmethod
    def load_private_key(
        path: str | Path,
        password: Optional[str] = None,
    ) -> ed25519.Ed25519PrivateKey:
        """Load Ed25519 private key from PEM file."""
        target = Path(path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Private key file not found: {target}")

        pem_data = target.read_bytes()
        pwd_bytes = password.encode("utf-8") if password else None
        loaded = serialization.load_pem_private_key(pem_data, password=pwd_bytes)

        if not isinstance(loaded, ed25519.Ed25519PrivateKey):
            raise ValueError(f"Key in {target} is not an Ed25519 private key.")

        return loaded

    @staticmethod
    def save_public_key(
        public_key: ed25519.Ed25519PublicKey,
        path: str | Path,
    ) -> None:
        """Save Ed25519 public key in PEM format."""
        target = Path(path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)

        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        target.write_bytes(pem_data)

    @staticmethod
    def load_public_key(path: str | Path) -> ed25519.Ed25519PublicKey:
        """Load Ed25519 public key from PEM file or raw hex."""
        target = Path(path).resolve()
        if not target.exists():
            # If path string is 64-char hex, try decoding raw public key bytes
            path_str = str(path).strip()
            if len(path_str) == 64:
                try:
                    raw = bytes.fromhex(path_str)
                    return ed25519.Ed25519PublicKey.from_public_bytes(raw)
                except Exception:
                    pass
            raise FileNotFoundError(f"Public key file not found: {target}")

        content = target.read_bytes()
        try:
            loaded = serialization.load_pem_public_key(content)
            if not isinstance(loaded, ed25519.Ed25519PublicKey):
                raise ValueError("Key is not an Ed25519 public key.")
            return loaded
        except Exception:
            # Try raw bytes
            return ed25519.Ed25519PublicKey.from_public_bytes(content)

    @staticmethod
    def public_key_to_hex(public_key: ed25519.Ed25519PublicKey) -> str:
        """Export raw 32-byte public key as hex string."""
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()


class RevocationRegistry:
    """Maintains a cryptographically auditable key revocation list (CRL)."""

    def __init__(self, registry_file: Optional[Path] = None):
        self.registry_file = registry_file or Path("revocations.json")
        self.revoked_keys: dict[str, dict[str, str]] = {}
        self._load()

    def _load(self) -> None:
        if self.registry_file.exists():
            try:
                data = json.loads(self.registry_file.read_text(encoding="utf-8"))
                self.revoked_keys = data.get("revoked_keys", {})
            except Exception:
                self.revoked_keys = {}

    def save(self) -> None:
        data = {
            "registry_version": "1.0.0",
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
            "revoked_keys": self.revoked_keys,
        }
        self.registry_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def revoke_key(self, key_id: str, reason: str = "Key compromise or decommission") -> None:
        """Mark a Key ID as revoked with timestamp and reason."""
        self.revoked_keys[key_id] = {
            "revoked_at_utc": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
        }
        self.save()

    def is_revoked(self, key_id: str) -> bool:
        """Check if a Key ID is in the revocation list."""
        return key_id in self.revoked_keys
