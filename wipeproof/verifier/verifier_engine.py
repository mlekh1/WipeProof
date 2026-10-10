"""
WipeProof Certificate Verification Engine.

Independently validates wipe certificates against RFC 8785 canonicalization,
RFC 8032 Ed25519 signatures, and key revocation lists.
Returns explicit status: VALID, INVALID, or REVOKED with forensic details.
"""

from __future__ import annotations
import hashlib
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from wipeproof.crypto.canonicalize import canonicalize_jcs
from wipeproof.crypto.keys import KeyManager, RevocationRegistry


class VerificationStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    REVOKED = "REVOKED"


@dataclass
class VerificationReport:
    """Detailed verification outcome for a certificate."""
    status: VerificationStatus
    reason: str
    certificate_id: str
    key_id: str
    canonical_payload_sha256: str
    calculated_payload_sha256: str
    device_serial: Optional[str] = None
    sanitization_method: Optional[str] = None
    sanitization_level: Optional[str] = None
    details: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class CertificateVerifier:
    """Verifies cryptographic authenticity and integrity of WipeProof certificates."""

    def __init__(
        self,
        revocation_registry: Optional[RevocationRegistry] = None,
    ):
        self.revocation_registry = revocation_registry

    def verify_certificate(
        self,
        certificate: dict[str, Any],
        trusted_public_key: Optional[ed25519.Ed25519PublicKey | str | Path] = None,
        expected_previous_hash: Optional[str] = None,
    ) -> VerificationReport:
        """Verify authenticity, payload integrity, and revocation status of a certificate.
        
        Args:
            certificate: Certificate JSON dictionary.
            trusted_public_key: Optional trusted public key (object, PEM file path, or 64-char hex).
                If omitted, uses the public key embedded in the certificate's signature block.
            expected_previous_hash: Optional expected previous hash to verify hash-chain continuity.
            
        Returns:
            VerificationReport with VALID, INVALID, or REVOKED status and reasons.
        """
        cert_id = certificate.get("certificate_id", "UNKNOWN")
        sig_block = certificate.get("signature")

        # 1. Structural Check
        if not sig_block or not isinstance(sig_block, dict):
            return VerificationReport(
                status=VerificationStatus.INVALID,
                reason="Malformed certificate: Missing or invalid 'signature' block.",
                certificate_id=cert_id,
                key_id="UNKNOWN",
                canonical_payload_sha256="",
                calculated_payload_sha256="",
            )

        key_id = sig_block.get("key_id", "UNKNOWN")
        reported_hash = sig_block.get("canonical_payload_sha256", "")
        sig_hex = sig_block.get("signature_hex", "")
        dev_serial = certificate.get("device", {}).get("serial")
        method = certificate.get("sanitization", {}).get("method_invoked")
        level = certificate.get("sanitization", {}).get("standard_mapping", {}).get("level")

        # 2. Key Revocation Check
        if self.revocation_registry and self.revocation_registry.is_revoked(key_id):
            return VerificationReport(
                status=VerificationStatus.REVOKED,
                reason=f"Signing key '{key_id}' has been REVOKED by the issuing authority.",
                certificate_id=cert_id,
                key_id=key_id,
                canonical_payload_sha256=reported_hash,
                calculated_payload_sha256="",
                device_serial=dev_serial,
                sanitization_method=method,
                sanitization_level=level,
            )

        # 3. Canonicalization & Payload Integrity Check
        raw_payload = {k: v for k, v in certificate.items() if k != "signature"}
        try:
            canonical_bytes = canonicalize_jcs(raw_payload)
            calculated_hash = hashlib.sha256(canonical_bytes).hexdigest()
        except Exception as e:
            return VerificationReport(
                status=VerificationStatus.INVALID,
                reason=f"Failed to canonicalize certificate payload: {e}",
                certificate_id=cert_id,
                key_id=key_id,
                canonical_payload_sha256=reported_hash,
                calculated_payload_sha256="",
            )

        if calculated_hash.lower() != reported_hash.lower():
            return VerificationReport(
                status=VerificationStatus.INVALID,
                reason=(
                    f"TAMPER DETECTED: Canonical SHA-256 payload digest mismatch. "
                    f"Expected {reported_hash}, but computed {calculated_hash}. "
                    "One or more fields in the certificate have been altered after signing."
                ),
                certificate_id=cert_id,
                key_id=key_id,
                canonical_payload_sha256=reported_hash,
                calculated_payload_sha256=calculated_hash,
                device_serial=dev_serial,
            )

        # 4. Resolve Public Key
        pub_key: ed25519.Ed25519PublicKey
        if trusted_public_key is not None:
            if isinstance(trusted_public_key, ed25519.Ed25519PublicKey):
                pub_key = trusted_public_key
            else:
                try:
                    pub_key = KeyManager.load_public_key(trusted_public_key)
                except Exception as e:
                    return VerificationReport(
                        status=VerificationStatus.INVALID,
                        reason=f"Failed to load trusted public key: {e}",
                        certificate_id=cert_id,
                        key_id=key_id,
                        canonical_payload_sha256=reported_hash,
                        calculated_payload_sha256=calculated_hash,
                    )
        else:
            # Fall back to embedded public key in certificate
            pub_hex = sig_block.get("public_key_hex")
            if not pub_hex:
                return VerificationReport(
                    status=VerificationStatus.INVALID,
                    reason="No trusted public key provided and certificate lacks 'public_key_hex'.",
                    certificate_id=cert_id,
                    key_id=key_id,
                    canonical_payload_sha256=reported_hash,
                    calculated_payload_sha256=calculated_hash,
                )
            try:
                raw_pub_bytes = bytes.fromhex(pub_hex)
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub_bytes)
            except Exception as e:
                return VerificationReport(
                    status=VerificationStatus.INVALID,
                    reason=f"Invalid embedded public key bytes: {e}",
                    certificate_id=cert_id,
                    key_id=key_id,
                    canonical_payload_sha256=reported_hash,
                    calculated_payload_sha256=calculated_hash,
                )

        # 5. Ed25519 Cryptographic Signature Verification
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            pub_key.verify(sig_bytes, canonical_bytes)
        except (InvalidSignature, ValueError):
            return VerificationReport(
                status=VerificationStatus.INVALID,
                reason="CRYPTOGRAPHIC SIGNATURE VERIFICATION FAILED: Signature is invalid for provided public key.",
                certificate_id=cert_id,
                key_id=key_id,
                canonical_payload_sha256=reported_hash,
                calculated_payload_sha256=calculated_hash,
                device_serial=dev_serial,
            )

        # 6. Optional Hash-Chain Verification
        if expected_previous_hash is not None:
            actual_prev = certificate.get("audit", {}).get("previous_certificate_hash")
            if actual_prev != expected_previous_hash:
                return VerificationReport(
                    status=VerificationStatus.INVALID,
                    reason=(
                        f"HASH CHAIN BROKEN: Expected previous hash {expected_previous_hash}, "
                        f"but certificate contains {actual_prev}."
                    ),
                    certificate_id=cert_id,
                    key_id=key_id,
                    canonical_payload_sha256=reported_hash,
                    calculated_payload_sha256=calculated_hash,
                    device_serial=dev_serial,
                )

        # All checks passed!
        return VerificationReport(
            status=VerificationStatus.VALID,
            reason="Certificate is cryptographically VALID, authentic, and unmodified.",
            certificate_id=cert_id,
            key_id=key_id,
            canonical_payload_sha256=reported_hash,
            calculated_payload_sha256=calculated_hash,
            device_serial=dev_serial,
            sanitization_method=method,
            sanitization_level=level,
            details={
                "tool_version": certificate.get("station", {}).get("tool_version"),
                "completed_at": certificate.get("timestamps", {}).get("completed_at"),
                "verification_passed": certificate.get("verification", {}).get("verification_passed"),
            },
        )
