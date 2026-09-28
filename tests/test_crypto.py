"""
Cryptographic unit and property-based tests for WipeProof.
Validates:
- RFC 8785 JSON Canonicalization Scheme (JCS) determinism
- Key generation, serialization, and revocation checks
- Certificate Notary signing and Ed25519 verification
- Hash chaining continuity
- PDF certificate generation with embedded QR codes
- Property-based tests via Hypothesis
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path
import pytest
from hypothesis import given, strategies as st
from cryptography.hazmat.primitives.asymmetric import ed25519

from wipeproof.core.models import (
    DeviceProfile,
    HpaDcoState,
    MediaType,
    SanitizationLevel,
    SanitizationMethod,
    VerificationResult,
    WipeResult,
)
from wipeproof.crypto.canonicalize import canonicalize_jcs
from wipeproof.crypto.keys import KeyManager, RevocationRegistry
from wipeproof.crypto.notary import CertificateNotary, GENESIS_HASH
from wipeproof.crypto.pdf_cert import CertificatePdfGenerator


def test_jcs_key_sorting():
    """Different dictionary key orders must canonicalize to identical byte streams."""
    dict_a = {"z": 100, "a": 1, "m": {"sub_b": 2, "sub_a": 1}}
    dict_b = {"a": 1, "m": {"sub_a": 1, "sub_b": 2}, "z": 100}

    bytes_a = canonicalize_jcs(dict_a)
    bytes_b = canonicalize_jcs(dict_b)

    assert bytes_a == bytes_b
    assert bytes_a == b'{"a":1,"m":{"sub_a":1,"sub_b":2},"z":100}'


def test_jcs_number_formatting():
    """Verify ECMAScript number formatting rules under RFC 8785."""
    assert canonicalize_jcs({"num": -0.0}) == b'{"num":0}'
    assert canonicalize_jcs({"num": 0.0}) == b'{"num":0}'
    assert canonicalize_jcs({"num": 42.0}) == b'{"num":42}'
    assert canonicalize_jcs({"num": 3.14159}) == b'{"num":3.14159}'


def test_jcs_string_escaping():
    """Verify strict escaping rules: quote and backslash escaped; slash not escaped."""
    obj = {"url": "https://example.com/test", "quote": 'hello "world"', "path": "C:\\Windows"}
    result = canonicalize_jcs(obj).decode("utf-8")
    assert '"url":"https://example.com/test"' in result
    assert '"quote":"hello \\"world\\""' in result
    assert '"path":"C:\\\\Windows"' in result


@given(st.dictionaries(keys=st.text(min_size=1, max_size=10), values=st.integers()))
def test_jcs_hypothesis_determinism(data):
    """Property-based test: Any dictionary serialized twice produces identical bytes."""
    bytes1 = canonicalize_jcs(data)
    bytes2 = canonicalize_jcs(data)
    assert bytes1 == bytes2


def test_key_manager_lifecycle():
    """Test generating, saving, loading keys and calculating Key IDs."""
    priv, pub = KeyManager.generate_keypair()
    key_id = KeyManager.get_key_id(pub)
    assert key_id.startswith("wp-key-")
    assert len(key_id) > 10

    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path = Path(tmpdir) / "test_private.pem"
        pub_path = Path(tmpdir) / "test_public.pem"

        KeyManager.save_private_key(priv, priv_path, password="secretpassword")
        KeyManager.save_public_key(pub, pub_path)

        assert priv_path.exists()
        assert pub_path.exists()

        loaded_priv = KeyManager.load_private_key(priv_path, password="secretpassword")
        loaded_pub = KeyManager.load_public_key(pub_path)

        assert KeyManager.get_key_id(loaded_pub) == key_id


def test_revocation_registry():
    """Verify revocation list operations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        reg_file = Path(tmpdir) / "revocations.json"
        registry = RevocationRegistry(reg_file)

        assert registry.is_revoked("wp-key-1234") is False

        registry.revoke_key("wp-key-1234", reason="Decommissioned")
        assert registry.is_revoked("wp-key-1234") is True

        # Reload from disk
        reloaded = RevocationRegistry(reg_file)
        assert reloaded.is_revoked("wp-key-1234") is True


def test_certificate_notary_signing_and_hash_chain():
    """Verify complete certificate creation, Ed25519 signature validity, and hash chaining."""
    priv, pub = KeyManager.generate_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        chain_file = Path(tmpdir) / "chain.json"
        notary = CertificateNotary(private_key=priv, chain_state_file=chain_file)

        # Mock WipeResult
        dev = DeviceProfile(
            path="/dev/loop0",
            model="Samsung SSD 870",
            serial="S5Y2NJ0N123456X",
            size_bytes=1000204886016,
            media_type=MediaType.SATA_SSD,
            hpa_dco=HpaDcoState(hpa_detected=False, native_max_sectors_before=1000, native_max_sectors_after=1000),
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
            details="All sampled sectors verified zero.",
        )
        wipe_res_1 = WipeResult(
            job_id="urn:uuid:11111111-1111-1111-1111-111111111111",
            device=dev,
            method=SanitizationMethod.ATA_SANITIZE_BLOCK_ERASE,
            level=SanitizationLevel.PURGE,
            standard_reference="NIST_SP_800_88_REV_2_PURGE",
            started_at="2026-09-20T18:00:00Z",
            completed_at="2026-09-20T18:05:00Z",
            duration_seconds=300.0,
            firmware_reported_status="SUCCESS",
            verification=ver,
            audit_log_sha256="abc123audit",
            success=True,
        )

        # Issue Certificate 1
        cert_1 = notary.issue_certificate(wipe_res_1)
        assert cert_1["audit"]["previous_certificate_hash"] == GENESIS_HASH

        # Verify mathematical signature of Certificate 1
        sig_info_1 = cert_1["signature"]
        raw_payload_1 = {k: v for k, v in cert_1.items() if k != "signature"}
        canonical_bytes_1 = canonicalize_jcs(raw_payload_1)

        # Hash check
        assert hashlib.sha256(canonical_bytes_1).hexdigest() == sig_info_1["canonical_payload_sha256"]

        # Signature verify
        sig_bytes_1 = bytes.fromhex(sig_info_1["signature_hex"])
        pub.verify(sig_bytes_1, canonical_bytes_1)  # Does not raise!

        # Issue Certificate 2 (Chain check)
        wipe_res_2 = WipeResult(
            job_id="urn:uuid:22222222-2222-2222-2222-222222222222",
            device=dev,
            method=SanitizationMethod.ATA_SANITIZE_BLOCK_ERASE,
            level=SanitizationLevel.PURGE,
            standard_reference="NIST_SP_800_88_REV_2_PURGE",
            started_at="2026-09-20T18:10:00Z",
            completed_at="2026-09-20T18:15:00Z",
            duration_seconds=300.0,
            firmware_reported_status="SUCCESS",
            verification=ver,
            audit_log_sha256="def456audit",
            success=True,
        )
        cert_2 = notary.issue_certificate(wipe_res_2)

        # Cert 2 previous_certificate_hash MUST match Cert 1 canonical_payload_sha256!
        assert cert_2["audit"]["previous_certificate_hash"] == sig_info_1["canonical_payload_sha256"]


def test_pdf_generation():
    """Verify that CertificatePdfGenerator produces a valid, readable PDF file."""
    priv, _ = KeyManager.generate_keypair()
    notary = CertificateNotary(private_key=priv)

    dev = DeviceProfile(
        path="/dev/loop0",
        model="Test SSD",
        serial="SN-PDF-TEST-99",
        size_bytes=500000000000,
        media_type=MediaType.SATA_SSD,
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
        job_id="urn:uuid:abcdef01-2345-6789-abcd-ef0123456789",
        device=dev,
        method=SanitizationMethod.OVERWRITE_ZERO,
        level=SanitizationLevel.CLEAR,
        standard_reference="NIST_SP_800_88_REV_2_CLEAR",
        started_at="2026-09-20T19:00:00Z",
        completed_at="2026-09-20T19:10:00Z",
        duration_seconds=600.0,
        firmware_reported_status="SUCCESS",
        verification=ver,
        audit_log_sha256="1234567890abcdef" * 4,
        success=True,
        disclaimer="NIST Clear only: Overwrite does not reach overprovisioned blocks.",
    )

    cert = notary.issue_certificate(wipe_res)

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "cert.pdf"
        gen = CertificatePdfGenerator()
        out = gen.generate_pdf(cert, pdf_path)

        assert Path(out).exists()
        assert Path(out).stat().st_size > 1000

        # Check valid PDF header
        with open(out, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"
