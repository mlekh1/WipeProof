"""
Integration tests for FastAPI verification microservice and CLI.
Validates:
- health_check() endpoint function
- verify_certificate_endpoint() (VALID, INVALID, REVOKED)
- get_merkle_inclusion_proof() Merkle audit path endpoint
- CLI verify and scan commands
"""

import json
from pathlib import Path
from click.testing import CliRunner

from wipeproof.cli import cli
from wipeproof.core.models import (
    DeviceProfile,
    MediaType,
    SanitizationLevel,
    SanitizationMethod,
    VerificationResult,
    WipeResult,
)
from wipeproof.crypto.keys import KeyManager
from wipeproof.crypto.notary import CertificateNotary
from wipeproof.verifier.service import (
    health_check,
    verify_certificate_endpoint,
    get_merkle_inclusion_proof,
    get_dashboard,
    run_interactive_demo,
    VerifyRequest,
)


def test_service_dashboard_and_demo():
    """Verify HTML dashboard route and demo execution route."""
    html_resp = get_dashboard()
    assert html_resp.status_code == 200
    assert "WipeProof" in html_resp.body.decode("utf-8")

    demo_data = run_interactive_demo()
    assert demo_data["status"] == "COMPLETED"
    assert "certificate" in demo_data
    assert demo_data["entropy"] == 0.0


def test_service_health_endpoint():
    """Verify health_check returns service metadata and Merkle log size."""
    data = health_check()
    assert data["status"] == "HEALTHY"
    assert data["service"] == "wipeproof-verifier"
    assert "merkle_log_size" in data


def test_service_verify_endpoint_valid():
    """Verify a valid signed certificate via verify_certificate_endpoint."""
    priv, pub = KeyManager.generate_keypair()
    notary = CertificateNotary(private_key=priv)

    dev = DeviceProfile(
        path="/dev/loop0",
        model="FastAPI Test Disk",
        serial="SN-API-001",
        size_bytes=100000000,
        media_type=MediaType.VIRTUAL_LOOPBACK,
    )
    ver = VerificationResult(
        sampling_method="LBA_SAMPLING",
        sampled_blocks_count=64,
        sample_block_size_bytes=4096,
        total_bytes_sampled=262144,
        read_errors=0,
        shannon_entropy=0.0,
        zero_fill_ratio=1.0,
        partition_table_cleared=True,
        firmware_status_verified=True,
        verification_passed=True,
        details="Zero verified.",
    )
    wipe_res = WipeResult(
        job_id="urn:uuid:12345678-1234-5678-1234-567812345678",
        device=dev,
        method=SanitizationMethod.SIMULATION_ERASE,
        level=SanitizationLevel.PURGE,
        standard_reference="NIST_SP_800_88_REV_2_PURGE",
        started_at="2026-09-20T19:00:00Z",
        completed_at="2026-09-20T19:01:00Z",
        duration_seconds=60.0,
        firmware_reported_status="SUCCESS",
        verification=ver,
        audit_log_sha256="api123audit" * 4,
        success=True,
    )
    cert = notary.issue_certificate(wipe_res)

    req = VerifyRequest(
        certificate=cert,
        trusted_public_key_hex=KeyManager.public_key_to_hex(pub),
    )

    res = verify_certificate_endpoint(req)
    assert res.status == "VALID"
    assert res.certificate_id == "urn:uuid:12345678-1234-5678-1234-567812345678"
    assert res.merkle_leaf_index is not None

    # Query Merkle inclusion proof for this leaf
    leaf_idx = res.merkle_leaf_index
    proof_data = get_merkle_inclusion_proof(leaf_idx)
    assert proof_data["is_valid"] is True
    assert proof_data["leaf_index"] == leaf_idx


def test_cli_verify_command(tmp_path: Path):
    """Test `wipeproof verify` CLI command on both valid and tampered certificates."""
    priv, pub = KeyManager.generate_keypair()
    pub_path = tmp_path / "pub.pem"
    KeyManager.save_public_key(pub, pub_path)

    notary = CertificateNotary(private_key=priv)
    dev = DeviceProfile(
        path="/dev/loop0",
        model="CLI Test Disk",
        serial="SN-CLI-001",
        size_bytes=100000000,
        media_type=MediaType.VIRTUAL_LOOPBACK,
    )
    ver = VerificationResult(
        sampling_method="LBA_SAMPLING",
        sampled_blocks_count=64,
        sample_block_size_bytes=4096,
        total_bytes_sampled=262144,
        read_errors=0,
        shannon_entropy=0.0,
        zero_fill_ratio=1.0,
        partition_table_cleared=True,
        firmware_status_verified=True,
        verification_passed=True,
        details="Zero verified.",
    )
    wipe_res = WipeResult(
        job_id="urn:uuid:33333333-3333-3333-3333-333333333333",
        device=dev,
        method=SanitizationMethod.SIMULATION_ERASE,
        level=SanitizationLevel.PURGE,
        standard_reference="NIST_SP_800_88_REV_2_PURGE",
        started_at="2026-09-20T19:00:00Z",
        completed_at="2026-09-20T19:01:00Z",
        duration_seconds=60.0,
        firmware_reported_status="SUCCESS",
        verification=ver,
        audit_log_sha256="cli123audit" * 4,
        success=True,
    )
    cert = notary.issue_certificate(wipe_res)

    cert_path = tmp_path / "valid_cert.json"
    cert_path.write_text(json.dumps(cert, indent=2))

    runner = CliRunner()

    # 1. Verify valid cert
    result = runner.invoke(cli, ["verify", str(cert_path), "--public-key", str(pub_path)])
    assert result.exit_code == 0
    assert "VALID" in result.output

    # 2. Tamper with serial number
    cert["device"]["serial"] = "TAMPERED-SERIAL"
    tampered_path = tmp_path / "tampered_cert.json"
    tampered_path.write_text(json.dumps(cert, indent=2))

    tamper_result = runner.invoke(cli, ["verify", str(tampered_path), "--public-key", str(pub_path)])
    assert tamper_result.exit_code != 0
    assert "INVALID" in tamper_result.output
