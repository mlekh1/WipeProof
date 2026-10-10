"""
WipeProof Cryptographic Certificate Notary.

Assembles versioned wipe certificates, enforces RFC 8785 canonicalization,
signs canonical payloads using RFC 8032 Ed25519, and manages cryptographic hash chaining.
"""

from __future__ import annotations
import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from wipeproof import __version__
from wipeproof.core.models import WipeResult
from wipeproof.crypto.canonicalize import canonicalize_jcs
from wipeproof.crypto.keys import KeyManager

GENESIS_HASH = "0" * 64


class CertificateNotary:
    """Signs wipe results and generates tamper-evident JSON certificates."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        key_id: Optional[str] = None,
        chain_state_file: Optional[Path] = None,
        operator_id: str = "operator-01",
    ):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id or KeyManager.get_key_id(self.public_key)
        self.public_key_hex = KeyManager.public_key_to_hex(self.public_key)
        self.chain_state_file = chain_state_file or Path(".wipeproof_chain.json")
        self.operator_id = operator_id

    def issue_certificate(
        self,
        wipe_result: WipeResult,
        override_previous_hash: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create, canonicalize, sign, and hash-chain a wipe certificate.
        
        Args:
            wipe_result: Result object from core sanitization orchestrator.
            override_previous_hash: Optional previous hash for testing chain continuity.
            
        Returns:
            Fully signed and validated certificate dictionary.
        """
        prev_hash = override_previous_hash or self._get_previous_certificate_hash()
        commit_hash = self._get_git_commit_hash()

        # Build unsigned payload
        payload: dict[str, Any] = {
            "$schema": "https://wipeproof.org/schema/v1/certificate.json",
            "certificate_id": wipe_result.job_id,
            "schema_version": "1.0.0",
            "station": {
                "hostname": platform.node() or "wipe-station",
                "tool_name": "wipeproof",
                "tool_version": __version__,
                "tool_commit_hash": commit_hash,
                "operator_id": self.operator_id,
            },
            "timestamps": {
                "started_at": wipe_result.started_at,
                "completed_at": wipe_result.completed_at,
                "duration_seconds": wipe_result.duration_seconds,
            },
            "device": wipe_result.device.to_dict(),
            "sanitization": {
                "method_invoked": wipe_result.method.value,
                "standard_mapping": {
                    "standard": "NIST_SP_800_88_REV_2",
                    "level": wipe_result.level.value,
                    "reference": wipe_result.standard_reference,
                },
                "firmware_reported_status": wipe_result.firmware_reported_status,
                "disclaimer": wipe_result.disclaimer,
            },
            "verification": wipe_result.verification.to_dict(),
            "audit": {
                "execution_log_sha256": wipe_result.audit_log_sha256,
                "previous_certificate_hash": prev_hash,
            },
        }

        # Step 1: Canonicalize payload using RFC 8785 (JCS)
        canonical_bytes = canonicalize_jcs(payload)

        # Step 2: Compute SHA-256 digest of canonical bytes
        canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        # Step 3: Sign canonical bytes with RFC 8032 Ed25519
        signature_bytes = self.private_key.sign(canonical_bytes)
        signature_hex = signature_bytes.hex()

        # Step 4: Assemble complete certificate
        certificate = {
            **payload,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": self.key_id,
                "public_key_hex": self.public_key_hex,
                "canonical_payload_sha256": canonical_sha256,
                "signature_hex": signature_hex,
            },
        }

        # Step 5: Update chain state with this certificate's canonical hash
        self._update_chain_state(canonical_sha256)

        return certificate

    def _get_previous_certificate_hash(self) -> str:
        """Read the latest certificate hash from the local chain state file."""
        if self.chain_state_file.exists():
            try:
                data = json.loads(self.chain_state_file.read_text(encoding="utf-8"))
                latest_hash = data.get("latest_certificate_hash", GENESIS_HASH)
                if isinstance(latest_hash, str):
                    return latest_hash
            except Exception:
                pass
        return GENESIS_HASH

    def _update_chain_state(self, new_hash: str) -> None:
        """Record the new latest certificate hash to preserve chain continuity."""
        data = {
            "chain_version": "1.0.0",
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
            "latest_certificate_hash": new_hash,
        }
        self.chain_state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def _get_git_commit_hash() -> str:
        """Fetch current git commit hash if running in a repo."""
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
        return "UNKNOWN_COMMIT_DEV_BUILD"
