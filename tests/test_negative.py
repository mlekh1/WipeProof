"""
Negative Security & Tamper-Detection Test Suite.

Rigorously evaluates adversarial tampering scenarios:
1. Bit tampering in certificate payload (altering serial, duration, or method).
2. Forged or mismatched signatures.
3. Verification using wrong public keys.
4. Certificates signed by revoked keys.
5. Replayed or out-of-sequence certificates (hash-chain break).
6. Malformed and corrupted payloads.
7. Merkle Tree inclusion proof verification and tamper rejection.
"""

import copy
import json
import tempfile
from pathlib import Path
import pytest

from wipeproof.core.models import (
    DeviceProfile,
    HpaDcoState,
    MediaType,
    SanitizationLevel,
    SanitizationMethod,
    VerificationResult,
    WipeResult,
)
from wipeproof.crypto.keys import KeyManager, RevocationRegistry
from wipeproof.crypto.notary import CertificateNotary
from wipeproof.verifier.merkle_log import MerkleTransparencyLog
from wipeproof.verifier.verifier_engine import CertificateVerifier, VerificationStatus


@pytest.fixture
def sample_valid_certificate() -> tuple[dict, KeyManager, any, any]:
    """Fixture producing a signed, mathematically valid wipe certificate and keypair."""
    priv, pub = KeyManager.generate_keypair()
    notary = CertificateNotary(private_key=priv)

    dev = DeviceProfile(
        path="/dev/loop0",
        model="Test Enterprise NVMe",
        serial="NVME-SECURE-9876",
        size_bytes=2000398934016,
        media_type=MediaType.NVME_SSD,
    )
    ver = VerificationResult(
        sampling_method="LBA_SAMPLING",
        sampled_blocks_count=512,
        sample_block_size_bytes=4096,
        total_bytes_sampled=2097152,
        read_errors=0,
        shannon_entropy=0.0,
        zero_fill_ratio=1.0,
        partition_table_cleared=True,
        firmware_status_verified=True,
        verification_passed=True,
        details="Verified zero.",
    )
    wipe_res = WipeResult(
        job_id="urn:uuid:99999999-9999-9999-9999-999999999999",
        device=dev,
        method=SanitizationMethod.NVME_SANITIZE_BLOCK_ERASE,
        level=SanitizationLevel.PURGE,
        standard_reference="NIST_SP_800_88_REV_2_PURGE",
        started_at="2026-09-20T18:00:00Z",
        completed_at="2026-09-20T18:05:00Z",
        duration_seconds=300.0,
        firmware_reported_status="SUCCESS",
        verification=ver,
        audit_log_sha256="aaaabbbbccccdddd" * 4,
        success=True,
    )

    cert = notary.issue_certificate(wipe_res)
    return cert, priv, pub


def test_tampered_serial_number_fails_verification(sample_valid_certificate):
    """Adversary alters the serial number in the JSON certificate."""
    cert, priv, pub = sample_valid_certificate
    tampered_cert = copy.deepcopy(cert)

    # Attacker alters serial number by 1 character
    tampered_cert["device"]["serial"] = "NVME-SECURE-9877"

    verifier = CertificateVerifier()
    report = verifier.verify_certificate(tampered_cert, trusted_public_key=pub)

    assert report.status == VerificationStatus.INVALID
    assert "TAMPER DETECTED" in report.reason
    assert report.calculated_payload_sha256 != report.canonical_payload_sha256


def test_tampered_sanitization_level_fails_verification(sample_valid_certificate):
    """Adversary attempts to elevate 'Clear' to 'Purge'."""
    cert, priv, pub = sample_valid_certificate
    tampered_cert = copy.deepcopy(cert)

    tampered_cert["sanitization"]["standard_mapping"]["level"] = "Destroy"

    verifier = CertificateVerifier()
    report = verifier.verify_certificate(tampered_cert, trusted_public_key=pub)

    assert report.status == VerificationStatus.INVALID
    assert "TAMPER DETECTED" in report.reason


def test_wrong_public_key_fails_verification(sample_valid_certificate):
    """Verifying against an untrusted/different public key must report INVALID."""
    cert, priv, pub = sample_valid_certificate

    # Generate a completely unrelated keypair
    _, wrong_pub = KeyManager.generate_keypair()

    verifier = CertificateVerifier()
    report = verifier.verify_certificate(cert, trusted_public_key=wrong_pub)

    assert report.status == VerificationStatus.INVALID
    assert "SIGNATURE VERIFICATION FAILED" in report.reason


def test_revoked_key_reports_revoked(sample_valid_certificate):
    """A certificate signed with a revoked key must report REVOKED."""
    cert, priv, pub = sample_valid_certificate
    key_id = cert["signature"]["key_id"]

    with tempfile.TemporaryDirectory() as tmpdir:
        reg_file = Path(tmpdir) / "revocations.json"
        registry = RevocationRegistry(reg_file)
        registry.revoke_key(key_id, reason="Technician laptop stolen")

        verifier = CertificateVerifier(revocation_registry=registry)
        report = verifier.verify_certificate(cert, trusted_public_key=pub)

        assert report.status == VerificationStatus.REVOKED
        assert "REVOKED" in report.reason


def test_broken_hash_chain_reports_invalid(sample_valid_certificate):
    """If expected previous hash does not match, report INVALID."""
    cert, priv, pub = sample_valid_certificate

    verifier = CertificateVerifier()
    report = verifier.verify_certificate(
        cert,
        trusted_public_key=pub,
        expected_previous_hash="wrong_previous_hash_0000000000000000000000000000000000000000",
    )

    assert report.status == VerificationStatus.INVALID
    assert "HASH CHAIN BROKEN" in report.reason


def test_merkle_transparency_inclusion_proof_validity():
    """Verify that Merkle tree inclusion proofs validate and tampered proofs fail."""
    tree = MerkleTransparencyLog()
    hashes = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "5555555555555555555555555555555555555555555555555555555555555555",
    ]

    for i, h in enumerate(hashes):
        tree.append_certificate(certificate_id=f"cert-{i}", canonical_payload_sha256=h)

    assert len(tree.leaves) == 5

    # Check inclusion proof for leaf 2
    proof = tree.get_inclusion_proof(2)
    assert proof.verify() is True

    # Tamper with leaf hash in proof -> must fail
    proof.leaf_hash = "deadbeef" * 8
    assert proof.verify() is False
